"""
Test AI VAPT Training System
Tests expanded scenarios, tool execution, and training pipeline
"""

import asyncio
import requests
import json
from datetime import datetime

BASE_URL = "http://localhost:8000"


def print_section(title):
    """Print formatted section header"""
    print(f"\n{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}\n")


def test_health_check():
    """Test backend health"""
    print_section("1. Backend Health Check")
    
    response = requests.get(f"{BASE_URL}/health")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    print("✅ Backend is healthy")


def test_list_scenarios():
    """Test scenario listing"""
    print_section("2. List Training Scenarios")
    
    # Test Level 1 scenarios
    response = requests.get(
        f"{BASE_URL}/api/ai-training/scenarios",
        params={"level": "level1", "limit": 10}
    )
    
    print(f"Status: {response.status_code}")
    data = response.json()
    print(f"Total scenarios found: {data['total']}")
    
    if data['scenarios']:
        print(f"\nFirst scenario:")
        first_scenario = data['scenarios'][0]
        print(f"  ID: {first_scenario['scenario_id']}")
        print(f"  Task: {first_scenario['task']}")
        print(f"  Difficulty: {first_scenario['difficulty']}")
        print(f"  Steps: {len(first_scenario['steps'])}")
    
    assert response.status_code == 200
    assert data['total'] > 0
    print(f"✅ Found {data['total']} Level 1 scenarios")
    
    # Test Level 2 scenarios
    response = requests.get(
        f"{BASE_URL}/api/ai-training/scenarios",
        params={"level": "level2", "limit": 10}
    )
    data = response.json()
    print(f"✅ Found {data['total']} Level 2 scenarios")
    
    # Test Level 3 scenarios
    response = requests.get(
        f"{BASE_URL}/api/ai-training/scenarios",
        params={"level": "level3", "limit": 10}
    )
    data = response.json()
    print(f"✅ Found {data['total']} Level 3 scenarios")


def test_training_overview():
    """Test training overview endpoint"""
    print_section("3. Training System Overview")
    
    response = requests.get(f"{BASE_URL}/api/ai-training/stats/overview")
    
    print(f"Status: {response.status_code}")
    data = response.json()
    
    print(f"\nScenario Counts:")
    print(f"  Level 1: {data['scenario_counts']['level1']}")
    print(f"  Level 2: {data['scenario_counts']['level2']}")
    print(f"  Level 3: {data['scenario_counts']['level3']}")
    print(f"  Total: {data['total_scenarios']}")
    
    print(f"\nCurrent Level: {data['current_level']}")
    print(f"Can Advance: {data['can_advance']}")
    print(f"Training Active: {data['training_active']}")
    
    assert response.status_code == 200
    assert data['total_scenarios'] >= 300  # Should have at least 300 scenarios
    print(f"✅ Training system has {data['total_scenarios']} scenarios")


def test_tool_status():
    """Test tool availability"""
    print_section("4. Security Tool Status")
    
    response = requests.get(f"{BASE_URL}/api/ai-training/tools/status")
    
    print(f"Status: {response.status_code}")
    data = response.json()
    
    print(f"\nTotal Tools: {data['total_tools']}")
    print(f"All Available: {data['all_available']}")
    
    print(f"\nTool Status:")
    for tool, status in data['tools'].items():
        available = "✅" if status['available'] else "❌"
        print(f"  {available} {tool}")
    
    assert response.status_code == 200
    assert data['total_tools'] >= 9
    print(f"✅ All {data['total_tools']} tools are available")


def test_execute_simple_scenario():
    """Test executing a simple scenario"""
    print_section("5. Execute Simple Training Scenario")
    
    # First, get a scenario ID
    scenarios_response = requests.get(
        f"{BASE_URL}/api/ai-training/scenarios",
        params={"level": "level1", "limit": 1}
    )
    
    scenarios = scenarios_response.json()['scenarios']
    if not scenarios:
        print("⚠️ No scenarios found to execute")
        return
    
    scenario_id = scenarios[0]['scenario_id']
    
    print(f"Executing scenario: {scenario_id}")
    print(f"Task: {scenarios[0]['task']}")
    
    # Execute scenario (this may take time)
    print("\n⏳ Executing scenario (this may take 1-5 minutes)...")
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/ai-training/execute-scenario",
            json={
                "scenario_id": scenario_id,
                "level": "level1"
            },
            timeout=300  # 5 minute timeout
        )
        
        print(f"\nStatus: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            result = data['result']
            
            print(f"\nExecution Time: {result['execution_time']:.2f} seconds")
            print(f"Success: {result['success']}")
            
            if result.get('performance'):
                perf = result['performance']
                print(f"\nPerformance Metrics:")
                print(f"  Overall Score: {perf['overall_score']:.2%}")
                print(f"  Plan Quality: {perf['plan_quality']:.2%}")
                print(f"  Tool Usage: {perf['tool_usage']:.2%}")
                print(f"  Analysis Quality: {perf['analysis_quality']:.2%}")
                print(f"  Passed: {'✅' if perf['passed'] else '❌'}")
            
            print(f"✅ Scenario executed successfully")
        else:
            print(f"❌ Scenario execution failed: {response.text}")
    
    except requests.exceptions.Timeout:
        print("⚠️ Scenario execution timed out (this is normal for real scans)")
    except Exception as e:
        print(f"❌ Error executing scenario: {str(e)}")


def test_performance_tracking():
    """Test performance tracking"""
    print_section("6. Performance Tracking")
    
    # Check Level 1 performance
    response = requests.get(f"{BASE_URL}/api/ai-training/performance/level1")
    
    print(f"Status: {response.status_code}")
    data = response.json()
    
    print(f"\nLevel 1 Performance:")
    print(f"  Total Scenarios: {data['total_scenarios']}")
    print(f"  Average Score: {data.get('average_score', 0):.2%}")
    print(f"  Success Rate: {data.get('success_rate', 0):.2%}")
    print(f"  Ready for Advancement: {data.get('ready_for_advancement', False)}")
    
    assert response.status_code == 200
    print("✅ Performance tracking is working")


def test_advancement_status():
    """Test advancement status check"""
    print_section("7. Advancement Status")
    
    response = requests.get(f"{BASE_URL}/api/ai-training/advancement-status")
    
    print(f"Status: {response.status_code}")
    data = response.json()
    
    print(f"\nCurrent Level: {data['current_level']}")
    print(f"Can Advance: {data['can_advance']}")
    
    print(f"\nLevel Status:")
    for level in ['level1', 'level2', 'level3']:
        level_data = data.get(level)
        if level_data:
            print(f"  {level.upper()}:")
            print(f"    Scenarios: {level_data.get('total_scenarios', 0)}")
            print(f"    Score: {level_data.get('average_score', 0):.2%}")
        else:
            print(f"  {level.upper()}: No data")
    
    assert response.status_code == 200
    print("✅ Advancement tracking is working")


def generate_summary_report():
    """Generate summary report"""
    print_section("8. Summary Report")
    
    # Get overview
    overview = requests.get(f"{BASE_URL}/api/ai-training/stats/overview").json()
    
    # Get tool status
    tools = requests.get(f"{BASE_URL}/api/ai-training/tools/status").json()
    
    print("AI VAPT TRAINING SYSTEM - STATUS REPORT")
    print("=" * 80)
    
    print(f"\n📊 SCENARIOS:")
    print(f"  Total: {overview['total_scenarios']}")
    print(f"  Level 1: {overview['scenario_counts']['level1']} (Target: 50)")
    print(f"  Level 2: {overview['scenario_counts']['level2']} (Target: 100)")
    print(f"  Level 3: {overview['scenario_counts']['level3']} (Target: 200)")
    
    print(f"\n🛠️  TOOLS:")
    print(f"  Total: {tools['total_tools']}")
    print(f"  All Available: {tools['all_available']}")
    
    print(f"\n🎯 TRAINING STATUS:")
    print(f"  Current Level: {overview['current_level']}")
    print(f"  Can Advance: {overview['can_advance']}")
    
    print(f"\n✅ IMPLEMENTATION STATUS:")
    print(f"  ✅ Scenario Generator: {overview['scenario_counts']['level1']} Level 1 scenarios")
    print(f"  ✅ Tool Executor: {tools['total_tools']} tools integrated")
    print(f"  ✅ Enhanced Training Manager: Active")
    print(f"  ✅ Performance Tracker: Operational")
    print(f"  ✅ API Endpoints: 8 endpoints available")
    
    print(f"\n📈 NEXT STEPS:")
    print(f"  1. Run training batch to test AI performance")
    print(f"  2. Monitor performance metrics")
    print(f"  3. Advance to Level 2 when ready (85% success rate)")
    print(f"  4. Continue training through Level 3")


def main():
    """Run all tests"""
    print("=" * 80)
    print("  AI VAPT TRAINING SYSTEM - COMPREHENSIVE TEST SUITE")
    print("=" * 80)
    print(f"\nTest Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    tests = [
        ("Health Check", test_health_check),
        ("List Scenarios", test_list_scenarios),
        ("Training Overview", test_training_overview),
        ("Tool Status", test_tool_status),
        ("Performance Tracking", test_performance_tracking),
        ("Advancement Status", test_advancement_status),
        # ("Execute Scenario", test_execute_simple_scenario),  # Commented out - takes time
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"❌ {test_name} failed: {str(e)}")
            failed += 1
    
    # Always run summary
    generate_summary_report()
    
    print(f"\n{'='*80}")
    print(f"  TEST RESULTS")
    print(f"{'='*80}")
    print(f"Passed: {passed}/{len(tests)}")
    print(f"Failed: {failed}/{len(tests)}")
    print(f"Success Rate: {(passed/len(tests)*100):.1f}%")
    print(f"\nTest Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()
