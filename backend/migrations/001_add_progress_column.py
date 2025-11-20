"""
Database migration: Add progress column to scans table
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2

DB_CONFIG = {
    'host': 'localhost',
    'port': 5433,
    'database': 'cybersec_ai',
    'user': 'postgres',
    'password': 'password'
}

def run_migration():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Add progress column
        cursor.execute("""
            ALTER TABLE scans 
            ADD COLUMN IF NOT EXISTS progress INTEGER DEFAULT 0
        """)
        
        conn.commit()
        cursor.close()
        conn.close()
        
        print("✓ Migration complete: Added progress column to scans table")
        
    except Exception as e:
        print(f"✗ Migration failed: {e}")

if __name__ == "__main__":
    run_migration()
