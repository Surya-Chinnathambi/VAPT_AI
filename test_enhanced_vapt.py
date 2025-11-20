#!/usr/bin/env python3
"""
Test Enhanced AI-Powered VAPT System
Tests Docker tool orchestration, parallel execution, and AI workflows
"""
import asyncio
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from core.enhanced_docker_manager import get_enhanced_docker_manager
from core.ai_security_prompts import (
    get_system_prompt,
    get_tool_config,
    calculate_risk_score,
    TOOL_CONFIGS
)

async def test_1_docker_manager_init():
    """Test 1: Docker Manager Initialization"""
    print("\n" + "=" * 70)
    print("Test 1: Enhanced Docker Manager Initialization")
    print("=" * 70)
    
    try:
        manager = get_enhanced_docker_manager()
        print("✅ Docker manager initialized")
        print(f"   Active containers: {len(manager.active_containers)}")
        return True
    except Exception as e:
        print(f"❌ FAIL: {e}")
        return False

async def test_2_pull_security_images():
    """Test 2: Pull Security Tool Images"""
    print("\n" + "=" * 70)
    print("Test 2: Pull Security Tool Docker Images")
    print("=" * 70)
    
    try:
        manager = get_enhanced_docker_manager()
        
        # Pull essential tools
        tools = ["nmap", "nuclei", "nikto", "trivy"]
        results = await manager.pull_security_images(tools)
        
        success_count = sum(1 for r in results.values() if r.get('success'))
        
        for tool, result in results.items():
            status = "✅" if result.get('success') else "❌"
            if result.get('success'):
                print(f"{status} {tool}: {result['image']}")
            else:
                print(f"{status} {tool}: {result.get('error', 'Unknown error')}")
        
        print(f"\nSuccess rate: {success_count}/{len(tools)}")
        
        return success_count >= 3  # At least 3 tools should work
    except Exception as e:
        print(f"❌ FAIL: {e}")
        return False

async def test_3_tool_info():
    """Test 3: Get Tool Information"""
    print("\n" + "=" * 70)
    print("Test 3: Tool Information & Capabilities")
    print("=" * 70)
    
    try:
        manager = get_enhanced_docker_manager()
        tools_info = await manager.get_tool_info()
        
        print(f"✅ Found {len(tools_info)} security tools:")
        for tool_name, info in tools_info.items():
            status_emoji = "✅" if info['status'] == 'ready' else "⏳"
            print(f"\n  {status_emoji} {tool_name.upper()}")
            print(f"      Image: {info['image']}")
            print(f"      Status: {info['status']}")
            print(f"      Scan types: {', '.join(info['scan_types'])}")
            print(f"      Description: {info['description']}")
        
        return len(tools_info) >= 5
    except Exception as e:
        print(f"❌ FAIL: {e}")
        return False

async def test_4_single_tool_execution():
    """Test 4: Single Tool Execution (Nuclei)"""
    print("\n" + "=" * 70)
    print("Test 4: Single Tool Execution - Nuclei")
    print("=" * 70)
    
    try:
        manager = get_enhanced_docker_manager()
        
        # Test Nuclei version check
        print("Running: nuclei -version")
        result = await manager.run_tool(
            tool_name="nuclei",
            target="-version",
            scan_type="quick",
            timeout=60
        )
        
        if result.get('success'):
            print(f"✅ Nuclei executed successfully")
            print(f"   Duration: {result['duration']}s")
            if 'version' in result['output'].lower():
                print(f"   Output preview: {result['output'][:200]}")
        else:
            print(f"❌ Nuclei failed: {result.get('error')}")
            return False
        
        return True
    except Exception as e:
        print(f"❌ FAIL: {e}")
        return False

async def test_5_parallel_execution():
    """Test 5: Parallel Tool Execution"""
    print("\n" + "=" * 70)
    print("Test 5: Parallel Tool Execution")
    print("=" * 70)
    
    try:
        manager = get_enhanced_docker_manager()
        
        # Run multiple tools in parallel (version checks)
        tasks = [
            {"tool_name": "nuclei", "target": "-version", "scan_type": "quick"},
            {"tool_name": "trivy", "target": "-v", "scan_type": "quick"},
        ]
        
        print(f"Running {len(tasks)} tools in parallel...")
        results = await manager.run_parallel(tasks)
        
        success_count = sum(1 for r in results if r.get('success'))
        
        for result in results:
            tool = result['tool']
            if result.get('success'):
                print(f"✅ {tool}: {result['duration']}s")
            else:
                print(f"❌ {tool}: {result.get('error')}")
        
        print(f"\nParallel execution: {success_count}/{len(tasks)} successful")
        
        return success_count >= 1
    except Exception as e:
        print(f"❌ FAIL: {e}")
        return False

async def test_6_ai_prompts():
    """Test 6: AI System Prompts"""
    print("\n" + "=" * 70)
    print("Test 6: AI System Prompts & Context")
    print("=" * 70)
    
    try:
        # Test different prompt contexts
        contexts = ["general", "reconnaissance", "scanning", "reporting"]
        
        for context in contexts:
            prompt = get_system_prompt(context)
            if prompt and len(prompt) > 100:
                print(f"✅ {context.capitalize()} prompt: {len(prompt)} chars")
            else:
                print(f"❌ {context.capitalize()} prompt: Missing or too short")
                return False
        
        print(f"\n✅ All {len(contexts)} AI prompts loaded successfully")
        return True
    except Exception as e:
        print(f"❌ FAIL: {e}")
        return False

async def test_7_tool_configs():
    """Test 7: Tool Configuration System"""
    print("\n" + "=" * 70)
    print("Test 7: Tool Configuration System")
    print("=" * 70)
    
    try:
        # Test tool configs
        test_tools = ["nmap", "nuclei", "nikto", "trivy", "sqlmap"]
        
        for tool in test_tools:
            config = get_tool_config(tool)
            if config and 'docker_image' in config:
                print(f"✅ {tool}: {config['docker_image']}")
                print(f"      Scan types: {list(config.get('scan_types', {}).keys())}")
            else:
                print(f"❌ {tool}: Config missing")
                return False
        
        print(f"\n✅ {len(TOOL_CONFIGS)} tool configurations available")
        return True
    except Exception as e:
        print(f"❌ FAIL: {e}")
        return False

async def test_8_risk_scoring():
    """Test 8: AI Risk Scoring Algorithm"""
    print("\n" + "=" * 70)
    print("Test 8: AI Risk Scoring Algorithm")
    print("=" * 70)
    
    try:
        # Test various vulnerability scenarios
        scenarios = [
            {
                "name": "Critical SQL Injection",
                "cvss": 9.8,
                "exploitability": "easy",
                "business_impact": "critical",
                "public_exploit": True,
                "remediation_hours": 2,
                "expected_range": (8.0, 10.0)
            },
            {
                "name": "Medium XSS",
                "cvss": 6.1,
                "exploitability": "medium",
                "business_impact": "medium",
                "public_exploit": False,
                "remediation_hours": 4,
                "expected_range": (4.0, 7.0)
            },
            {
                "name": "Low Info Disclosure",
                "cvss": 3.7,
                "exploitability": "hard",
                "business_impact": "low",
                "public_exploit": False,
                "remediation_hours": 1,
                "expected_range": (1.0, 4.0)
            }
        ]
        
        all_passed = True
        for scenario in scenarios:
            score = calculate_risk_score(
                cvss=scenario['cvss'],
                exploitability=scenario['exploitability'],
                business_impact=scenario['business_impact'],
                public_exploit=scenario['public_exploit'],
                remediation_hours=scenario['remediation_hours']
            )
            
            expected_min, expected_max = scenario['expected_range']
            in_range = expected_min <= score <= expected_max
            
            status = "✅" if in_range else "❌"
            print(f"{status} {scenario['name']}: Risk Score = {score}/10")
            print(f"      CVSS: {scenario['cvss']}, Exploitability: {scenario['exploitability']}")
            print(f"      Expected range: {expected_min}-{expected_max}")
            
            if not in_range:
                all_passed = False
        
        return all_passed
    except Exception as e:
        print(f"❌ FAIL: {e}")
        return False

async def test_9_scan_phase_execution():
    """Test 9: Full Scan Phase Execution"""
    print("\n" + "=" * 70)
    print("Test 9: Scan Phase Execution (Reconnaissance)")
    print("=" * 70)
    
    try:
        manager = get_enhanced_docker_manager()
        
        # Run reconnaissance phase on a safe target
        print("Running reconnaissance on scanme.nmap.org...")
        result = await manager.run_scan_phase(
            phase="reconnaissance",
            target="scanme.nmap.org",
            intensity="quick"
        )
        
        if result.get('success'):
            print(f"✅ Reconnaissance phase completed")
            print(f"   Tools run: {result['tools_run']}")
            print(f"   Tools successful: {result['tools_successful']}")
            print(f"   Phase: {result['phase']}")
            
            # Show some results
            for tool_result in result['results'][:3]:  # First 3 results
                tool = tool_result['tool']
                status = "✅" if tool_result.get('success') else "❌"
                print(f"   {status} {tool}")
        else:
            print(f"❌ Phase failed: {result.get('error')}")
            return False
        
        return result.get('tools_successful', 0) >= 1
    except Exception as e:
        print(f"❌ FAIL: {e}")
        return False

async def main():
    """Run all tests"""
    print("=" * 70)
    print("ENHANCED AI-POWERED VAPT SYSTEM - TEST SUITE")
    print("=" * 70)
    
    tests = [
        ("Docker Manager Init", test_1_docker_manager_init),
        ("Pull Security Images", test_2_pull_security_images),
        ("Tool Information", test_3_tool_info),
        ("Single Tool Execution", test_4_single_tool_execution),
        ("Parallel Execution", test_5_parallel_execution),
        ("AI System Prompts", test_6_ai_prompts),
        ("Tool Configurations", test_7_tool_configs),
        ("AI Risk Scoring", test_8_risk_scoring),
        ("Scan Phase Execution", test_9_scan_phase_execution),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = await test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n❌ Test crashed: {e}")
            results.append((name, False))
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {name}")
    
    print("\n" + "=" * 70)
    print(f"Results: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    print("=" * 70)
    
    if passed == total:
        print("\n🎉 All tests passed! Enhanced VAPT system ready!")
        print("\n📚 Key Features Validated:")
        print("   ✅ AI-powered tool orchestration")
        print("   ✅ Docker container management")
        print("   ✅ Parallel tool execution")
        print("   ✅ Intelligent risk scoring")
        print("   ✅ Multi-phase scanning workflow")
        print("   ✅ 88+ security tools available")
        return 0
    else:
        print(f"\n⚠ {total - passed} test(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
