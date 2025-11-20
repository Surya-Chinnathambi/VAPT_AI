import os
import sys
from dotenv import load_dotenv

# Add backend to path
sys.path.append(os.getcwd())

try:
    from ai_training.training_manager import TrainingManager
except ImportError:
    from backend.ai_training.training_manager import TrainingManager

import asyncio

def test_ai_generation():
    load_dotenv()
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("⚠️  OPENAI_API_KEY not found in environment. Skipping real AI test.")
        return

    print(f"✅ Found OPENAI_API_KEY: {api_key[:5]}...{api_key[-5:]}")
    
    manager = TrainingManager()
    
    print("\n--- Testing Level 1 Scenario Generation ---")
    try:
        # Run async method
        asyncio.run(manager.run_training_session(level="basic", num_scenarios=1))
        print("✅ Scenario Execution Completed")
    except Exception as e:
        print(f"❌ Error generating scenario: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_ai_generation()
