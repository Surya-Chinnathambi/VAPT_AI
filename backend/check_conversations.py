import psycopg2
import redis

# Check database
conn = psycopg2.connect('postgresql://postgres:password@localhost:5433/cybersec_ai')
cur = conn.cursor()

cur.execute('SELECT COUNT(*) FROM chat_conversations')
conv_count = cur.fetchone()[0]
print(f'\n📊 Total conversations in DB: {conv_count}')

cur.execute('SELECT COUNT(*) FROM chat_messages')
msg_count = cur.fetchone()[0]
print(f'💬 Total messages in DB: {msg_count}')

cur.execute('''
    SELECT session_id, message_count, created_at, last_message_at 
    FROM chat_conversations 
    ORDER BY created_at DESC 
    LIMIT 1
''')
latest = cur.fetchone()
if latest:
    print(f'\n✅ Latest conversation:')
    print(f'   Session ID: {latest[0]}')
    print(f'   Messages: {latest[1]}')
    print(f'   Created: {latest[2]}')
    print(f'   Last message: {latest[3]}')
    
    # Get messages from this conversation
    cur.execute('''
        SELECT role, LEFT(content, 80) as content_preview, cm.created_at
        FROM chat_messages cm
        JOIN chat_conversations cc ON cm.conversation_id = cc.id
        WHERE cc.session_id = %s
        ORDER BY cm.created_at ASC
    ''', (latest[0],))
    messages = cur.fetchall()
    print(f'\n💬 Messages in conversation:')
    for i, msg in enumerate(messages, 1):
        print(f'   {i}. [{msg[0]}] {msg[1]}...')

conn.close()

# Check Redis
try:
    r = redis.from_url('redis://localhost:6380/0')
    r.ping()
    keys = r.keys('conversation:*')
    print(f'\n💾 Conversations cached in Redis: {len(keys)}')
    if keys:
        print(f'   Cache keys:')
        for key in keys[:3]:  # Show first 3
            print(f'      - {key.decode()}')
    print('\n✅ Redis cache operational!')
except Exception as e:
    print(f'\n⚠️ Redis error: {e}')

print('\n✅ Conversation memory verification complete!')
