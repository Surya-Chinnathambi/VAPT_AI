import psycopg2

conn = psycopg2.connect('postgresql://postgres:password@localhost:5433/cybersec_ai')
cur = conn.cursor()

# Check for conversation tables
cur.execute("SELECT table_name FROM information_schema.tables WHERE table_name LIKE 'chat_%'")
tables = cur.fetchall()

print("\n✅ Conversation tables created:")
for t in tables:
    print(f"   - {t[0]}")

# Check table structure
if tables:
    cur.execute("""
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_name = 'chat_conversations'
        ORDER BY ordinal_position
    """)
    columns = cur.fetchall()
    print("\n📋 chat_conversations structure:")
    for col in columns:
        print(f"   - {col[0]}: {col[1]}")
    
    cur.execute("""
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_name = 'chat_messages'
        ORDER BY ordinal_position
    """)
    columns = cur.fetchall()
    print("\n📋 chat_messages structure:")
    for col in columns:
        print(f"   - {col[0]}: {col[1]}")

# Check counts
cur.execute('SELECT COUNT(*) FROM chat_conversations')
count = cur.fetchone()[0]
print(f"\n📊 Total conversations: {count}")

conn.close()
print("\n✅ Database verification complete!")
