"""
Database migration: Add VAPT scan types to scans table
Alters the scan_type CHECK constraint to include vapt_full, vapt_recon, vapt_scan, vapt_exploit
"""
import psycopg2
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DATABASE_URL

def migrate():
    """Apply database migration"""
    conn = psycopg2.connect(DATABASE_URL)
    
    try:
        cursor = conn.cursor()
        
        print("🔄 Migrating database: Adding VAPT scan types...")
        
        # Drop old constraint
        cursor.execute("""
            ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_scan_type_check;
        """)
        
        # Add new constraint with VAPT types
        cursor.execute("""
            ALTER TABLE scans ADD CONSTRAINT scans_scan_type_check 
            CHECK (scan_type IN (
                'nmap', 'nikto', 'port_scan', 'web_scan', 'shodan',
                'vapt_full', 'vapt_recon', 'vapt_scan', 'vapt_exploit'
            ));
        """)
        
        conn.commit()
        print("✅ Migration successful: VAPT scan types added")
        
        # Verify
        cursor.execute("""
            SELECT conname, pg_get_constraintdef(oid) 
            FROM pg_constraint 
            WHERE conname = 'scans_scan_type_check';
        """)
        
        result = cursor.fetchone()
        if result:
            print(f"\n📋 New constraint: {result[1]}")
        
    except Exception as e:
        conn.rollback()
        print(f"❌ Migration failed: {e}")
        raise
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    migrate()
