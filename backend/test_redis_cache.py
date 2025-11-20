import redis
import json
from datetime import datetime

# Test Redis caching manually
r = redis.from_url('redis://localhost:6380/0', decode_responses=True)

# Test data
messages = [
    {"role": "user", "content": "Test message", "created_at": datetime.utcnow()},
    {"role": "assistant", "content": "Test response", "created_at": datetime.utcnow()}
]

# Convert datetime to string
serializable = []
for msg in messages:
    msg_copy = dict(msg)
    if 'created_at' in msg_copy:
        msg_copy['created_at'] = str(msg_copy['created_at'])
    serializable.append(msg_copy)

# Store in Redis
test_key = "conversation:test-session-123"
try:
    r.setex(test_key, 60, json.dumps(serializable))
    print("✅ Stored in Redis")
    
    # Retrieve
    cached = r.get(test_key)
    if cached:
        data = json.loads(cached)
        print(f"✅ Retrieved {len(data)} messages from Redis")
        print(f"   Message 1: {data[0]['content']}")
    
    # Check all keys
    keys = r.keys('conversation:*')
    print(f"\n💾 Total conversation keys: {len(keys)}")
    for k in keys:
        print(f"   - {k}")
    
    # Clean up
    r.delete(test_key)
    print("\n✅ Redis caching test successful!")
    
except Exception as e:
    print(f"❌ Error: {e}")
