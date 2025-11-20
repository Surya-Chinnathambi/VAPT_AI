/**
 * Frontend Load Testing - Concurrent Users
 * Simulates 2-3 concurrent users interacting with the application
 */

import { test, expect, chromium, Browser, BrowserContext, Page } from '@playwright/test';

interface UserSession {
    browser: Browser;
    context: BrowserContext;
    page: Page;
    userId: number;
    actions: number;
    errors: string[];
    responseTimes: number[];
}

class LoadTester {
    private sessions: UserSession[] = [];

    async createUserSession(userId: number): Promise<UserSession> {
        const browser = await chromium.launch({ headless: true });
        const context = await browser.newContext();
        const page = await context.newPage();

        return {
            browser,
            context,
            page,
            userId,
            actions: 0,
            errors: [],
            responseTimes: []
        };
    }

    async simulateUserActions(session: UserSession, duration: number = 30000) {
        const startTime = Date.now();
        const { page, userId } = session;

        try {
            // Navigate to application
            await page.goto('http://localhost:5173');
            await page.waitForLoadState('networkidle');

            // Login
            await this.loginUser(session, `testuser${userId}`, 'TestPass123!@#');

            // Perform random actions
            while (Date.now() - startTime < duration) {
                const action = this.getRandomAction();
                const actionStart = Date.now();

                try {
                    await this.performAction(session, action);
                    session.actions++;
                    session.responseTimes.push(Date.now() - actionStart);
                } catch (error) {
                    session.errors.push(`${action}: ${error.message}`);
                }

                // Random delay between actions
                await page.waitForTimeout(Math.random() * 2000 + 500);
            }
        } catch (error) {
            session.errors.push(`Session error: ${error.message}`);
        }
    }

    async loginUser(session: UserSession, username: string, password: string) {
        const { page } = session;

        // Check if already on login page
        const currentUrl = page.url();
        if (!currentUrl.includes('/login')) {
            await page.goto('http://localhost:5173/login');
        }

        // Fill login form
        await page.fill('input[name="username"], input[type="text"]', username);
        await page.fill('input[name="password"], input[type="password"]', password);

        // Submit
        await page.click('button[type="submit"]');

        // Wait for navigation
        await page.waitForTimeout(2000);
    }

    getRandomAction(): string {
        const actions = [
            'navigate-dashboard',
            'navigate-port-scanner',
            'navigate-web-scanner',
            'navigate-cve-database',
            'navigate-ai-chat',
            'search-cve',
            'view-reports'
        ];
        return actions[Math.floor(Math.random() * actions.length)];
    }

    async performAction(session: UserSession, action: string) {
        const { page } = session;

        switch (action) {
            case 'navigate-dashboard':
                await page.click('a[href*="dashboard"], text=Dashboard');
                await page.waitForLoadState('networkidle');
                break;

            case 'navigate-port-scanner':
                await page.click('a[href*="port"], text=Port Scanner');
                await page.waitForLoadState('networkidle');
                break;

            case 'navigate-web-scanner':
                await page.click('a[href*="web"], text=Web Scanner');
                await page.waitForLoadState('networkidle');
                break;

            case 'navigate-cve-database':
                await page.click('a[href*="cve"], text=CVE');
                await page.waitForLoadState('networkidle');
                break;

            case 'navigate-ai-chat':
                await page.click('a[href*="chat"], text=AI Chat');
                await page.waitForLoadState('networkidle');
                break;

            case 'search-cve':
                // Try to find search input
                const searchInput = await page.$('input[type="search"], input[placeholder*="search"]');
                if (searchInput) {
                    await searchInput.fill('apache');
                    await page.keyboard.press('Enter');
                    await page.waitForTimeout(1000);
                }
                break;

            case 'view-reports':
                await page.click('a[href*="report"], text=Reports');
                await page.waitForLoadState('networkidle');
                break;
        }
    }

    async cleanup() {
        for (const session of this.sessions) {
            await session.context.close();
            await session.browser.close();
        }
        this.sessions = [];
    }

    printResults() {
        console.log('\n' + '='.repeat(60));
        console.log('FRONTEND LOAD TEST RESULTS');
        console.log('='.repeat(60));

        let totalActions = 0;
        let totalErrors = 0;
        const allResponseTimes: number[] = [];

        this.sessions.forEach((session, index) => {
            totalActions += session.actions;
            totalErrors += session.errors.length;
            allResponseTimes.push(...session.responseTimes);

            console.log(`\nUser ${session.userId}:`);
            console.log(`  Actions: ${session.actions}`);
            console.log(`  Errors: ${session.errors.length}`);
            if (session.errors.length > 0) {
                console.log(`  Error samples: ${session.errors.slice(0, 3).join(', ')}`);
            }

            if (session.responseTimes.length > 0) {
                const avgTime = session.responseTimes.reduce((a, b) => a + b, 0) / session.responseTimes.length;
                console.log(`  Avg Response Time: ${avgTime.toFixed(0)}ms`);
            }
        });

        console.log(`\nOverall:`);
        console.log(`  Total Actions: ${totalActions}`);
        console.log(`  Total Errors: ${totalErrors}`);
        console.log(`  Success Rate: ${((totalActions - totalErrors) / totalActions * 100).toFixed(1)}%`);

        if (allResponseTimes.length > 0) {
            const avgResponseTime = allResponseTimes.reduce((a, b) => a + b, 0) / allResponseTimes.length;
            const maxResponseTime = Math.max(...allResponseTimes);
            const minResponseTime = Math.min(...allResponseTimes);

            console.log(`  Avg Response Time: ${avgResponseTime.toFixed(0)}ms`);
            console.log(`  Min Response Time: ${minResponseTime.toFixed(0)}ms`);
            console.log(`  Max Response Time: ${maxResponseTime.toFixed(0)}ms`);
        }
        console.log('='.repeat(60) + '\n');
    }
}

test.describe('Frontend Load Testing', () => {
    let loadTester: LoadTester;

    test.beforeEach(() => {
        loadTester = new LoadTester();
    });

    test.afterEach(async () => {
        await loadTester.cleanup();
    });

    test('2 concurrent users - 20 seconds each', async () => {
        console.log('\nStarting 2 concurrent users test...');

        // Create 2 user sessions
        const session1 = await loadTester.createUserSession(1);
        const session2 = await loadTester.createUserSession(2);

        loadTester['sessions'] = [session1, session2];

        // Run both sessions concurrently
        await Promise.all([
            loadTester.simulateUserActions(session1, 20000),
            loadTester.simulateUserActions(session2, 20000)
        ]);

        // Print results
        loadTester.printResults();

        // Assertions
        const totalActions = session1.actions + session2.actions;
        const totalErrors = session1.errors.length + session2.errors.length;

        expect(totalActions).toBeGreaterThan(0);
        expect(totalErrors / totalActions).toBeLessThan(0.2); // Less than 20% error rate
    });

    test('3 concurrent users - 20 seconds each', async () => {
        console.log('\nStarting 3 concurrent users test...');

        // Create 3 user sessions
        const session1 = await loadTester.createUserSession(1);
        const session2 = await loadTester.createUserSession(2);
        const session3 = await loadTester.createUserSession(3);

        loadTester['sessions'] = [session1, session2, session3];

        // Run all sessions concurrently
        await Promise.all([
            loadTester.simulateUserActions(session1, 20000),
            loadTester.simulateUserActions(session2, 20000),
            loadTester.simulateUserActions(session3, 20000)
        ]);

        // Print results
        loadTester.printResults();

        // Assertions
        const totalActions = session1.actions + session2.actions + session3.actions;
        const totalErrors = session1.errors.length + session2.errors.length + session3.errors.length;

        expect(totalActions).toBeGreaterThan(0);
        expect(totalErrors / totalActions).toBeLessThan(0.25); // Less than 25% error rate
    });

    test('Page load performance under concurrent access', async () => {
        console.log('\nTesting page load performance...');

        const loadTimes: number[] = [];

        // 3 browsers loading the same page simultaneously
        const browsers = await Promise.all([
            chromium.launch({ headless: true }),
            chromium.launch({ headless: true }),
            chromium.launch({ headless: true })
        ]);

        try {
            const pages = await Promise.all(
                browsers.map(async (browser: Browser) => {
                    const context = await browser.newContext();
                    return await context.newPage();
                })
            );            // Measure concurrent page loads
            const startTime = Date.now();
            await Promise.all(
                pages.map(async (page: Page) => {
                    const pageStart = Date.now();
                    await page.goto('http://localhost:5173');
                    await page.waitForLoadState('networkidle');
                    loadTimes.push(Date.now() - pageStart);
                })
            );
            const totalTime = Date.now() - startTime;

            console.log(`\nPage Load Results:`);
            console.log(`  Concurrent loads: 3`);
            console.log(`  Total time: ${totalTime}ms`);
            console.log(`  Individual load times: ${loadTimes.map(t => `${t}ms`).join(', ')}`);
            console.log(`  Average load time: ${(loadTimes.reduce((a, b) => a + b, 0) / loadTimes.length).toFixed(0)}ms`);

            // Assert all pages loaded in reasonable time
            loadTimes.forEach(time => {
                expect(time).toBeLessThan(10000); // 10 seconds max
            });

            // Close pages
            await Promise.all(pages.map((page: Page) => page.close()));
        } finally {
            // Close browsers
            await Promise.all(browsers.map((browser: Browser) => browser.close()));
        }
    });

    test('Memory leak detection - sustained navigation', async () => {
        console.log('\nTesting for memory leaks...');

        const session = await loadTester.createUserSession(1);
        const { page } = session;

        await page.goto('http://localhost:5173');

        // Get initial memory
        const initialMemory = await page.evaluate(() => {
            return (performance as any).memory?.usedJSHeapSize || 0;
        });

        // Navigate between pages 20 times
        for (let i = 0; i < 20; i++) {
            await page.click('a[href*="dashboard"]');
            await page.waitForTimeout(500);
            await page.click('a[href*="port"]');
            await page.waitForTimeout(500);
        }

        // Get final memory
        const finalMemory = await page.evaluate(() => {
            return (performance as any).memory?.usedJSHeapSize || 0;
        });

        const memoryIncrease = finalMemory - initialMemory;
        const memoryIncreaseMB = memoryIncrease / 1024 / 1024;

        console.log(`\nMemory Usage:`);
        console.log(`  Initial: ${(initialMemory / 1024 / 1024).toFixed(2)} MB`);
        console.log(`  Final: ${(finalMemory / 1024 / 1024).toFixed(2)} MB`);
        console.log(`  Increase: ${memoryIncreaseMB.toFixed(2)} MB`);

        // Assert memory increase is reasonable (less than 50MB)
        expect(memoryIncreaseMB).toBeLessThan(50);

        await session.browser.close();
    });
});
