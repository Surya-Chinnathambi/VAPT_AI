"""
PostgreSQL Database Connection Manager
"""
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import SimpleConnectionPool
from contextlib import contextmanager
import logging

from config import DATABASE_URL
from database.schema import ALL_TABLES, INSERT_COMPLIANCE_FRAMEWORKS

logger = logging.getLogger(__name__)

# Connection pool
pool = None

def init_connection_pool(min_connections=1, max_connections=10):
    """Initialize connection pool"""
    global pool
    try:
        pool = SimpleConnectionPool(
            min_connections,
            max_connections,
            DATABASE_URL
        )
        logger.info("Database connection pool initialized")
        return pool
    except Exception as e:
        logger.error(f"Failed to initialize connection pool: {e}")
        raise

@contextmanager
def get_db_connection():
    """Get database connection from pool"""
    global pool
    if pool is None:
        try:
            init_connection_pool()
        except Exception as e:
            logger.error(f"Failed to get database connection: {e}")
            raise Exception("Database connection pool not initialized") from e
    
    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Database error: {e}")
        raise
    finally:
        pool.putconn(conn)

@contextmanager
def get_db_cursor(commit=True):
    """Get database cursor with dict results"""
    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        try:
            yield cursor
            if commit:
                conn.commit()
        except Exception as e:
            conn.rollback()
            raise
        finally:
            cursor.close()

def init_database():
    """Initialize database schema"""
    try:
        with get_db_cursor() as cursor:
            # Create all tables
            for table_sql in ALL_TABLES:
                cursor.execute(table_sql)
            
            # Insert seed data
            cursor.execute(INSERT_COMPLIANCE_FRAMEWORKS)
            
        logger.info("Database schema initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

def check_database_health():
    """Check if database is accessible"""
    global pool
    try:
        # Try to initialize pool if not already done
        if pool is None:
            try:
                init_connection_pool()
            except Exception as pool_error:
                logger.error(f"Cannot initialize connection pool: {pool_error}")
                return False
        
        with get_db_cursor() as cursor:
            cursor.execute("SELECT 1")
            return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False

# Utility functions for common queries

def create_user(email: str, username: str, password_hash: str, role: str = 'free'):
    """Create a new user"""
    with get_db_cursor() as cursor:
        cursor.execute("""
            INSERT INTO users (email, username, password_hash, role)
            VALUES (%s, %s, %s, %s)
            RETURNING id, email, username, role, created_at
        """, (email, username, password_hash, role))
        return dict(cursor.fetchone())

def get_user_by_email(email: str):
    """Get user by email"""
    with get_db_cursor(commit=False) as cursor:
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()
        return dict(result) if result else None

def get_user_by_username(username: str):
    """Get user by username"""
    with get_db_cursor(commit=False) as cursor:
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()
        return dict(result) if result else None

def get_user_by_id(user_id: int):
    """Get user by ID"""
    with get_db_cursor(commit=False) as cursor:
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        result = cursor.fetchone()
        return dict(result) if result else None

def update_user_last_login(user_id: int):
    """Update user's last login timestamp"""
    with get_db_cursor() as cursor:
        cursor.execute("""
            UPDATE users 
            SET last_login = CURRENT_TIMESTAMP 
            WHERE id = %s
        """, (user_id,))

def create_scan(user_id: int, target: str, scan_type: str, tool: str):
    """Create a new scan record"""
    with get_db_cursor() as cursor:
        cursor.execute("""
            INSERT INTO scans (user_id, target, scan_type, tool, status, started_at)
            VALUES (%s, %s, %s, %s, 'running', CURRENT_TIMESTAMP)
            RETURNING id, user_id, target, scan_type, tool, status, created_at
        """, (user_id, target, scan_type, tool))
        return dict(cursor.fetchone())

def update_scan_status(scan_id: int, status: str, raw_output=None, summary=None, 
                       error_message=None, vulnerabilities_found=0, risk_level=None):
    """Update scan status and results"""
    with get_db_cursor() as cursor:
        cursor.execute("""
            UPDATE scans 
            SET status = %s, 
                raw_output = %s, 
                summary = %s, 
                error_message = %s,
                vulnerabilities_found = %s,
                risk_level = %s,
                completed_at = CASE WHEN %s IN ('completed', 'failed') THEN CURRENT_TIMESTAMP ELSE completed_at END
            WHERE id = %s
        """, (status, raw_output, summary, error_message, vulnerabilities_found, risk_level, status, scan_id))

def get_user_scans(user_id: int, limit: int = 10, offset: int = 0):
    """Get user's scan history"""
    with get_db_cursor(commit=False) as cursor:
        cursor.execute("""
            SELECT * FROM scans 
            WHERE user_id = %s 
            ORDER BY created_at DESC 
            LIMIT %s OFFSET %s
        """, (user_id, limit, offset))
        return [dict(row) for row in cursor.fetchall()]

def get_scan_by_id(scan_id: int, user_id: int = None):
    """Get scan by ID"""
    with get_db_cursor(commit=False) as cursor:
        if user_id:
            cursor.execute("SELECT * FROM scans WHERE id = %s AND user_id = %s", (scan_id, user_id))
        else:
            cursor.execute("SELECT * FROM scans WHERE id = %s", (scan_id,))
        result = cursor.fetchone()
        return dict(result) if result else None

def get_user_monthly_usage(user_id: int):
    """Get user's usage for current month"""
    with get_db_cursor(commit=False) as cursor:
        cursor.execute("""
            SELECT COUNT(*) as scan_count
            FROM scans 
            WHERE user_id = %s 
            AND created_at >= date_trunc('month', CURRENT_TIMESTAMP)
        """, (user_id,))
        result = cursor.fetchone()
        return result['scan_count'] if result else 0

def create_report(user_id: int, scan_id: int, report_name: str, report_type: str, 
                 format: str = 'pdf', compliance_frameworks=None):
    """Create a new report record"""
    with get_db_cursor() as cursor:
        cursor.execute("""
            INSERT INTO reports (user_id, scan_id, report_name, report_type, format, compliance_frameworks)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id, user_id, scan_id, report_name, report_type, status, created_at
        """, (user_id, scan_id, report_name, report_type, format, compliance_frameworks))
        return dict(cursor.fetchone())

def get_user_reports(user_id: int, limit: int = 20):
    """Get user's reports"""
    with get_db_cursor(commit=False) as cursor:
        cursor.execute("""
            SELECT r.*, s.target, s.scan_type 
            FROM reports r
            LEFT JOIN scans s ON r.scan_id = s.id
            WHERE r.user_id = %s 
            ORDER BY r.created_at DESC 
            LIMIT %s
        """, (user_id, limit))
        return [dict(row) for row in cursor.fetchall()]

def log_usage(user_id: int, action_type: str, resource_type: str = None, 
              resource_id: int = None, metadata: dict = None):
    """Log user action"""
    with get_db_cursor() as cursor:
        cursor.execute("""
            INSERT INTO usage_logs (user_id, action_type, resource_type, resource_id, metadata)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, action_type, resource_type, resource_id, metadata))
