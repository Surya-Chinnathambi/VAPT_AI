"""
CyberShieldAI - Production Monitoring Dashboard
Real-time monitoring of conversation storage and cache performance
"""
import psycopg2
import redis
import time
from datetime import datetime, timedelta
import json

class ConversationMonitor:
    def __init__(self):
        self.db_conn = psycopg2.connect('postgresql://postgres:password@localhost:5433/cybersec_ai')
        self.redis_client = redis.from_url('redis://localhost:6380/0', decode_responses=True)
        
    def get_database_stats(self):
        """Get database statistics"""
        cur = self.db_conn.cursor()
        
        # Total conversations
        cur.execute('SELECT COUNT(*) FROM chat_conversations WHERE is_active = TRUE')
        total_convs = cur.fetchone()[0]
        
        # Total messages
        cur.execute('SELECT COUNT(*) FROM chat_messages')
        total_msgs = cur.fetchone()[0]
        
        # Active conversations (last 24h)
        cur.execute('''
            SELECT COUNT(*) FROM chat_conversations 
            WHERE last_message_at > NOW() - INTERVAL '24 hours'
            AND is_active = TRUE
        ''')
        active_24h = cur.fetchone()[0]
        
        # Messages per conversation (average)
        cur.execute('''
            SELECT AVG(message_count)::int FROM chat_conversations 
            WHERE is_active = TRUE AND message_count > 0
        ''')
        avg_msgs = cur.fetchone()[0] or 0
        
        # Busiest hour (messages created)
        cur.execute('''
            SELECT EXTRACT(HOUR FROM created_at) as hour, COUNT(*) as count
            FROM chat_messages
            WHERE created_at > NOW() - INTERVAL '7 days'
            GROUP BY hour
            ORDER BY count DESC
            LIMIT 1
        ''')
        result = cur.fetchone()
        busiest_hour = f"{int(result[0])}:00" if result else "N/A"
        
        return {
            'total_conversations': total_convs,
            'total_messages': total_msgs,
            'active_24h': active_24h,
            'avg_messages_per_conv': avg_msgs,
            'busiest_hour': busiest_hour
        }
    
    def get_redis_stats(self):
        """Get Redis cache statistics"""
        keys = self.redis_client.keys('conversation:*')
        
        stats = {
            'cached_conversations': len(keys),
            'cache_keys': [k for k in keys[:5]],  # First 5 keys
            'memory_info': {}
        }
        
        # Get Redis info
        try:
            info = self.redis_client.info('memory')
            stats['memory_info'] = {
                'used_memory_human': info.get('used_memory_human', 'N/A'),
                'used_memory_peak_human': info.get('used_memory_peak_human', 'N/A'),
                'total_keys': len(self.redis_client.keys('*'))
            }
        except:
            pass
        
        return stats
    
    def get_performance_metrics(self):
        """Get performance metrics"""
        cur = self.db_conn.cursor()
        
        # Recent conversation load times (simulated)
        # In production, you'd log these from the application
        cur.execute('''
            SELECT 
                session_id,
                message_count,
                EXTRACT(EPOCH FROM (updated_at - created_at)) as duration
            FROM chat_conversations
            WHERE is_active = TRUE
            ORDER BY updated_at DESC
            LIMIT 10
        ''')
        
        recent_convs = []
        for row in cur.fetchall():
            recent_convs.append({
                'session_id': row[0][:8] + '...',
                'messages': row[1],
                'duration': f"{row[2]:.1f}s"
            })
        
        return {
            'recent_conversations': recent_convs
        }
    
    def check_cache_hit_rate(self):
        """Calculate cache hit rate (simplified)"""
        redis_keys = len(self.redis_client.keys('conversation:*'))
        
        cur = self.db_conn.cursor()
        cur.execute('''
            SELECT COUNT(*) FROM chat_conversations 
            WHERE last_message_at > NOW() - INTERVAL '1 hour'
            AND is_active = TRUE
        ''')
        active_recent = cur.fetchone()[0]
        
        if active_recent > 0:
            hit_rate = (redis_keys / active_recent) * 100
        else:
            hit_rate = 0
        
        return min(hit_rate, 100)  # Cap at 100%
    
    def get_user_activity(self):
        """Get user activity stats"""
        cur = self.db_conn.cursor()
        
        # Most active users
        cur.execute('''
            SELECT u.username, COUNT(cc.id) as conv_count, SUM(cc.message_count) as total_msgs
            FROM users u
            JOIN chat_conversations cc ON u.id = cc.user_id
            WHERE cc.is_active = TRUE
            GROUP BY u.username
            ORDER BY total_msgs DESC
            LIMIT 5
        ''')
        
        top_users = []
        for row in cur.fetchall():
            top_users.append({
                'username': row[0],
                'conversations': row[1],
                'messages': row[2]
            })
        
        return top_users
    
    def display_dashboard(self):
        """Display monitoring dashboard"""
        print("\n" + "="*80)
        print("           🔍 CYBERSHIELDAI CONVERSATION MONITORING 🔍")
        print("="*80 + "\n")
        
        # Database Stats
        print("📊 DATABASE STATISTICS")
        print("-" * 80)
        db_stats = self.get_database_stats()
        print(f"   Total Conversations:       {db_stats['total_conversations']:,}")
        print(f"   Total Messages:            {db_stats['total_messages']:,}")
        print(f"   Active (24h):              {db_stats['active_24h']:,}")
        print(f"   Avg Messages/Conv:         {db_stats['avg_messages_per_conv']}")
        print(f"   Busiest Hour:              {db_stats['busiest_hour']}")
        
        # Redis Cache Stats
        print("\n💾 REDIS CACHE STATISTICS")
        print("-" * 80)
        redis_stats = self.get_redis_stats()
        print(f"   Cached Conversations:      {redis_stats['cached_conversations']}")
        if redis_stats['memory_info']:
            print(f"   Memory Used:               {redis_stats['memory_info']['used_memory_human']}")
            print(f"   Peak Memory:               {redis_stats['memory_info']['used_memory_peak_human']}")
            print(f"   Total Keys:                {redis_stats['memory_info']['total_keys']}")
        
        # Cache Hit Rate
        hit_rate = self.check_cache_hit_rate()
        print(f"\n   Cache Hit Rate:            {hit_rate:.1f}%")
        
        # Performance Metrics
        print("\n⚡ PERFORMANCE METRICS")
        print("-" * 80)
        perf = self.get_performance_metrics()
        print("   Recent Conversations:")
        for conv in perf['recent_conversations'][:5]:
            print(f"      {conv['session_id']}: {conv['messages']} msgs in {conv['duration']}")
        
        # User Activity
        print("\n👥 USER ACTIVITY (TOP 5)")
        print("-" * 80)
        users = self.get_user_activity()
        for i, user in enumerate(users, 1):
            print(f"   {i}. {user['username']:15} {user['conversations']:3} convs, {user['messages']:4} msgs")
        
        # Health Status
        print("\n✅ SYSTEM HEALTH")
        print("-" * 80)
        print(f"   Database:                  {'🟢 CONNECTED' if self.db_conn else '🔴 ERROR'}")
        print(f"   Redis:                     {'🟢 CONNECTED' if self.redis_client.ping() else '🔴 ERROR'}")
        print(f"   Cache Performance:         {'🟢 EXCELLENT' if hit_rate > 70 else '🟡 GOOD' if hit_rate > 40 else '🔴 POOR'}")
        
        print("\n" + "="*80)
        print(f"   Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80 + "\n")
    
    def close(self):
        """Close connections"""
        if self.db_conn:
            self.db_conn.close()
        if self.redis_client:
            self.redis_client.close()

def main():
    """Run monitoring dashboard"""
    monitor = ConversationMonitor()
    
    try:
        while True:
            monitor.display_dashboard()
            
            print("📈 Monitoring active... (Ctrl+C to exit)")
            print("Refreshing in 30 seconds...\n")
            time.sleep(30)
            
    except KeyboardInterrupt:
        print("\n\n⏹️  Monitoring stopped by user")
    finally:
        monitor.close()
        print("✅ Monitoring session ended\n")

if __name__ == "__main__":
    main()
