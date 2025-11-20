# Quick Start Guide - Load Testing

## Issue Fixed ✅
The `chromadb` module was missing. It has now been installed along with all vector search dependencies:
- chromadb==0.4.22
- sentence-transformers==2.3.1  
- langchain==0.1.0
- langchain-openai==0.0.2
- langchain-community==0.0.10
- faiss-cpu==1.7.4

## How to Run Load Tests

### Step 1: Start Backend Server

In the **uvicorn terminal** that was running, the server should auto-reload. If it stopped, restart it:

```powershell
cd D:\CyberShieldAI\CyberShieldAI\backend
uvicorn main:app --reload
```

Wait for these success messages:
```
✅ Redis connected for conversation caching
✅ OpenAI/LiteLLM configured
INFO: Application startup complete
INFO: Uvicorn running on http://127.0.0.1:8000
```

### Step 2: Verify Backend is Running

```powershell
# Test health endpoint
Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing
```

Expected response: `200 OK` with `{"status":"healthy"}`

### Step 3: Run Load Tests

```powershell
cd D:\CyberShieldAI\CyberShieldAI\backend
python tests/test_simple_load.py
```

This will:
- ✅ Test 2 concurrent users (15 seconds each)
- ✅ Test 3 concurrent users (15 seconds each)
- ✅ Measure response times, success rates, throughput
- ✅ Provide deployment readiness assessment

### Expected Output

```
======================================================================
CyberShield AI - Concurrent User Load Testing
======================================================================

🔍 Checking Backend Availability...
✓ Backend server is running

======================================================================
LOAD TEST: 2 Concurrent Users (15s each)
======================================================================

📊 Test completed in 15.23s

Per-User Results:
----------------------------------------------------------------------
User 1:
  Requests: 24
  Success Rate: 95.8%
  Avg Response Time: 421ms
  ...

======================================================================
OVERALL RESULTS:
======================================================================
Total Requests: 46
Successful: 45 (97.8%)
...

======================================================================
DEPLOYMENT READINESS ASSESSMENT:
======================================================================
✓ Success Rate > 80%: 97.8% [PASS]
✓ Avg Response < 3s: 410ms [PASS]
✓ Max Response < 10s: 2103ms [PASS]
✓ No Critical Errors: 1 failures [PASS]

🎉 SYSTEM READY FOR DEPLOYMENT WITH 2-3 USERS! 🎉
```

## Alternative: Run All Dependencies Check

If you want to verify all dependencies are installed:

```powershell
cd D:\CyberShieldAI\CyberShieldAI\backend
pip list | Select-String -Pattern "chromadb|langchain|sentence-transformers"
```

Should show:
```
chromadb                   0.4.22
langchain                  0.1.0
langchain-community        0.0.10
langchain-openai           0.0.2
sentence-transformers      2.3.1
```

## Next: Start the Backend

The chromadb issue is now fixed. Simply restart the uvicorn server and run the load test!
