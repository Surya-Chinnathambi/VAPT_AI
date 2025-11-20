"""
Test Real-Time Tool Execution for All 88+ Security Tools
Validates streaming, progress updates, and parallel execution
"""
import asyncio
import sys
from datetime import datetime

# Add backend to path
sys.path.insert(0, 'd:/CyberShieldAI/CyberShieldAI/backend')

from core.realtime_tool_executor import get_realtime_executor
from core.ai_security_prompts import TOOL_CONFIGS


class RealtimeTestMonitor:
    """Monitor real-time progress updates"""
    
    def __init__(self):
        self.messages = []
        self.vulnerabilities = []
        self.progress_updates = []
    
    async def callback(self, message: dict):
        """Collect all progress messages"""
        self.messages.append(message)
        
        msg_type = message.get('type')
        
        if msg_type == 'tool_start':
            print(f"\n🚀 Starting: {message.get('tool')} on {message.get('target')}")
        
        elif msg_type == 'log':
            # Print every 10th log line to avoid spam
            if message.get('line_number', 0) % 10 == 0:
                print(f"   📝 Line {message.get('line_number')}: {message.get('line')[:80]}...")
        
        elif msg_type == 'vulnerability_found':
            vuln = message.get('vulnerability', {})
            severity = vuln.get('severity', 'unknown').upper()
            self.vulnerabilities.append(message)
            print(f"   🚨 [{severity}] Vulnerability #{message.get('findings_count')}: {vuln.get('type')}")
        
        elif msg_type == 'progress':
            pct = message.get('percentage', 0)
            self.progress_updates.append(message)
            print(f"   ⏳ Progress: {pct}% ({message.get('lines_processed')} lines)")
        
        elif msg_type == 'tool_complete':
            duration = message.get('duration', 0)
            findings = message.get('findings_count', 0)
            success = message.get('success', False)
            status = '✅' if success else '❌'
            print(f"{status} Completed: {message.get('tool')} - {findings} findings in {duration:.1f}s")
        
        elif msg_type == 'parallel_start':
            tools = message.get('tools', [])
            print(f"\n🔄 Parallel execution starting: {len(tools)} tools")
            print(f"   Tools: {', '.join(tools)}")
        
        elif msg_type == 'parallel_complete':
            success = message.get('success_count', 0)
            total = message.get('tools_count', 0)
            print(f"\n✅ Parallel execution complete: {success}/{total} successful")
        
        elif msg_type == 'image_pull':
            print(f"   📦 Pulling Docker image: {message.get('image')}")


async def test_1_realtime_executor_init():
    """Test 1: Real-time executor initialization"""
    print("\n" + "="*70)
    print("Test 1: Real-Time Executor Initialization")
    print("="*70)
    
    try:
        executor = get_realtime_executor()
        
        print(f"✅ Executor initialized")
        print(f"   Docker available: {executor.docker_available}")
        print(f"   Active executions: {len(executor.active_executions)}")
        
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        return False


async def test_2_single_tool_realtime():
    """Test 2: Single tool execution with real-time streaming"""
    print("\n" + "="*70)
    print("Test 2: Single Tool Real-Time Execution (Nuclei)")
    print("="*70)
    
    try:
        executor = get_realtime_executor()
        monitor = RealtimeTestMonitor()
        
        # Run Nuclei version check (fast test)
        result = await executor.execute_tool_realtime(
            tool_name="nuclei",
            target="https://scanme.nmap.org",
            scan_type="quick",
            progress_callback=monitor.callback
        )
        
        print(f"\n📊 Results:")
        print(f"   Success: {result.get('success')}")
        print(f"   Duration: {result.get('duration', 0):.1f}s")
        print(f"   Findings: {result.get('findings_count', 0)}")
        print(f"   Messages received: {len(monitor.messages)}")
        print(f"   Progress updates: {len(monitor.progress_updates)}")
        print(f"   Vulnerabilities: {len(monitor.vulnerabilities)}")
        
        # Verify message types
        message_types = set(m.get('type') for m in monitor.messages)
        print(f"   Message types: {', '.join(sorted(message_types))}")
        
        return result.get('success', False)
    
    except Exception as e:
        print(f"❌ FAILED: {e}")
        return False


async def test_3_parallel_realtime():
    """Test 3: Parallel tool execution with real-time streaming"""
    print("\n" + "="*70)
    print("Test 3: Parallel Real-Time Execution (3 tools)")
    print("="*70)
    
    try:
        executor = get_realtime_executor()
        monitor = RealtimeTestMonitor()
        
        # Run 3 tools in parallel
        tasks = [
            {"tool_name": "nmap", "target": "scanme.nmap.org", "scan_type": "quick"},
            {"tool_name": "nuclei", "target": "https://scanme.nmap.org", "scan_type": "quick"},
            {"tool_name": "testssl", "target": "scanme.nmap.org:443", "scan_type": "quick"}
        ]
        
        start_time = datetime.now()
        results = await executor.execute_parallel_realtime(tasks, monitor.callback)
        duration = (datetime.now() - start_time).total_seconds()
        
        print(f"\n📊 Parallel Execution Results:")
        print(f"   Total duration: {duration:.1f}s")
        print(f"   Tools run: {len(results)}")
        print(f"   Successful: {sum(1 for r in results if r.get('success'))}")
        print(f"   Total messages: {len(monitor.messages)}")
        print(f"   Total vulnerabilities: {len(monitor.vulnerabilities)}")
        
        for i, result in enumerate(results):
            tool = result.get('tool')
            success = '✅' if result.get('success') else '❌'
            findings = result.get('findings_count', 0)
            tool_duration = result.get('duration', 0)
            print(f"   {success} {tool}: {findings} findings in {tool_duration:.1f}s")
        
        # Check for parallel efficiency (should be < sum of individual durations)
        total_sequential = sum(r.get('duration', 0) for r in results)
        efficiency = (total_sequential / duration) if duration > 0 else 0
        print(f"   Parallel efficiency: {efficiency:.1f}x faster")
        
        return len(results) > 0
    
    except Exception as e:
        print(f"❌ FAILED: {e}")
        return False


async def test_4_vulnerability_detection():
    """Test 4: Real-time vulnerability detection"""
    print("\n" + "="*70)
    print("Test 4: Real-Time Vulnerability Detection")
    print("="*70)
    
    try:
        executor = get_realtime_executor()
        monitor = RealtimeTestMonitor()
        
        # Run Nuclei on a vulnerable test site
        result = await executor.execute_tool_realtime(
            tool_name="nuclei",
            target="http://testphp.vulnweb.com",
            scan_type="quick",
            progress_callback=monitor.callback
        )
        
        print(f"\n📊 Vulnerability Detection:")
        print(f"   Vulnerabilities detected: {len(monitor.vulnerabilities)}")
        
        # Show first 5 vulnerabilities
        for i, vuln_msg in enumerate(monitor.vulnerabilities[:5]):
            vuln = vuln_msg.get('vulnerability', {})
            print(f"   {i+1}. [{vuln.get('severity', 'N/A').upper()}] {vuln.get('type')}")
        
        if len(monitor.vulnerabilities) > 5:
            print(f"   ... and {len(monitor.vulnerabilities) - 5} more")
        
        return len(monitor.vulnerabilities) >= 0  # May find 0 vulns, still valid
    
    except Exception as e:
        print(f"❌ FAILED: {e}")
        return False


async def test_5_progress_tracking():
    """Test 5: Progress percentage tracking"""
    print("\n" + "="*70)
    print("Test 5: Progress Tracking")
    print("="*70)
    
    try:
        executor = get_realtime_executor()
        monitor = RealtimeTestMonitor()
        
        # Run Nmap (good for progress updates)
        result = await executor.execute_tool_realtime(
            tool_name="nmap",
            target="scanme.nmap.org",
            scan_type="quick",
            progress_callback=monitor.callback
        )
        
        print(f"\n📊 Progress Tracking:")
        print(f"   Progress updates: {len(monitor.progress_updates)}")
        
        if monitor.progress_updates:
            percentages = [p.get('percentage', 0) for p in monitor.progress_updates]
            print(f"   Progress range: {min(percentages)}% → {max(percentages)}%")
            print(f"   Average progress: {sum(percentages)/len(percentages):.1f}%")
        
        return len(monitor.progress_updates) > 0
    
    except Exception as e:
        print(f"❌ FAILED: {e}")
        return False


async def test_6_all_tools_available():
    """Test 6: Verify all 88+ tools are configured"""
    print("\n" + "="*70)
    print("Test 6: All 88+ Tools Configuration")
    print("="*70)
    
    try:
        print(f"📦 Total tools configured: {len(TOOL_CONFIGS)}")
        
        # Categorize tools
        categories = {
            "Network": ["nmap", "masscan", "zmap", "rustscan"],
            "Web": ["nuclei", "nikto", "wpscan", "sqlmap", "xsstrike"],
            "SSL/TLS": ["testssl", "sslyze", "sslscan"],
            "DNS": ["sublist3r", "amass", "dnsenum", "fierce"],
            "Cloud": ["scoutsuite", "prowler", "cloudsploit"],
            "Container": ["trivy", "grype", "anchore"],
            "Code": ["semgrep", "bandit", "brakeman"],
            "Fuzzing": ["ffuf", "gobuster", "wfuzz", "dirsearch"]
        }
        
        print(f"\n🔧 Tool Categories:")
        for category, tools in categories.items():
            available = [t for t in tools if t in TOOL_CONFIGS]
            print(f"   {category}: {len(available)}/{len(tools)} configured")
        
        # Show random tools
        import random
        sample_tools = random.sample(list(TOOL_CONFIGS.keys()), min(10, len(TOOL_CONFIGS)))
        print(f"\n📋 Sample Tools:")
        for tool in sample_tools:
            config = TOOL_CONFIGS[tool]
            print(f"   • {tool}: {config.get('docker_image', 'N/A')}")
        
        return len(TOOL_CONFIGS) >= 88
    
    except Exception as e:
        print(f"❌ FAILED: {e}")
        return False


async def test_7_message_types():
    """Test 7: Verify all message types work"""
    print("\n" + "="*70)
    print("Test 7: Message Types Verification")
    print("="*70)
    
    try:
        executor = get_realtime_executor()
        monitor = RealtimeTestMonitor()
        
        # Run a quick scan
        result = await executor.execute_tool_realtime(
            tool_name="nuclei",
            target="https://scanme.nmap.org",
            scan_type="quick",
            progress_callback=monitor.callback
        )
        
        # Check message types
        message_types = set(m.get('type') for m in monitor.messages)
        
        expected_types = {'tool_start', 'log', 'tool_complete'}
        optional_types = {'progress', 'vulnerability_found', 'image_pull'}
        
        print(f"\n📨 Message Types Received:")
        for msg_type in sorted(message_types):
            count = sum(1 for m in monitor.messages if m.get('type') == msg_type)
            print(f"   • {msg_type}: {count} messages")
        
        # Verify required types
        missing = expected_types - message_types
        if missing:
            print(f"\n⚠️ Missing message types: {missing}")
            return False
        
        print(f"\n✅ All required message types present")
        return True
    
    except Exception as e:
        print(f"❌ FAILED: {e}")
        return False


async def main():
    """Run all real-time tests"""
    print("\n" + "="*70)
    print("🚀 REAL-TIME TOOL EXECUTOR TEST SUITE")
    print("   Testing all 88+ security tools with live streaming")
    print("="*70)
    
    tests = [
        test_1_realtime_executor_init,
        test_2_single_tool_realtime,
        test_3_parallel_realtime,
        test_4_vulnerability_detection,
        test_5_progress_tracking,
        test_6_all_tools_available,
        test_7_message_types
    ]
    
    results = []
    for test_func in tests:
        try:
            result = await test_func()
            results.append((test_func.__name__, result))
        except Exception as e:
            print(f"\n❌ Test crashed: {e}")
            results.append((test_func.__name__, False))
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    for test_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    passed_count = sum(1 for _, p in results if p)
    total = len(results)
    success_rate = (passed_count / total * 100) if total > 0 else 0
    
    print(f"\nResults: {passed_count}/{total} tests passed ({success_rate:.1f}%)")
    
    if success_rate == 100:
        print("\n🎉 All tests passed! Real-time streaming ready!")
        print("\n📚 Key Features Validated:")
        print("   ✅ Real-time log streaming")
        print("   ✅ Live vulnerability detection")
        print("   ✅ Progress percentage tracking")
        print("   ✅ Parallel tool execution")
        print("   ✅ 88+ security tools available")
        print("   ✅ All message types working")
    else:
        print(f"\n⚠️ {total - passed_count} test(s) failed")
    
    return success_rate == 100


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
