from fastapi import APIRouter, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import jwt
import os
from datetime import datetime, timedelta

from models.user import UserCreate, UserLogin, Token, UserResponse
from core.rate_limiting import limiter

# Try to use PostgreSQL, fallback to SQLite
try:
    from database.connection import get_db_connection as get_pg_connection
    USE_POSTGRES = True
except:
    from utils.database import get_db_connection
    USE_POSTGRES = False

router = APIRouter()
security = HTTPBearer()
ph = PasswordHasher()

SESSION_SECRET = os.getenv("SESSION_SECRET", "dev_secret_key_not_for_production")

def create_access_token(user_id: int, username: str, role: str):
    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    token = jwt.encode(payload, SESSION_SECRET, algorithm='HS256')
    return token

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SESSION_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@router.post("/register", response_model=Token)
async def register(user: UserCreate, request: Request):
    if USE_POSTGRES:
        with get_pg_connection() as conn:
            cursor = conn.cursor()
            
            try:
                # Check if user exists (PostgreSQL)
                cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", 
                              (user.username, user.email))
                if cursor.fetchone():
                    raise HTTPException(status_code=400, detail="User already exists")
                
                hashed_password = ph.hash(user.password)
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, role, created_at)
                    VALUES (%s, %s, %s, 'free', NOW())
                    RETURNING id
                """, (user.username, user.email, hashed_password))
                
                user_id = cursor.fetchone()[0]
                
                access_token = create_access_token(
                    user_id=user_id,
                    username=user.username,
                    role='free'
                )
                
                return {"access_token": access_token, "token_type": "bearer"}
            finally:
                cursor.close()
    else:
        # SQLite fallback
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", 
                          (user.username, user.email))
            if cursor.fetchone():
                raise HTTPException(status_code=400, detail="User already exists")
            
            hashed_password = ph.hash(user.password)
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role, created_at)
                VALUES (?, ?, ?, 'free', ?)
            """, (user.username, user.email, hashed_password, datetime.now()))
            
            user_id = cursor.lastrowid
            conn.commit()
            
            access_token = create_access_token(
                user_id=user_id,
                username=user.username,
                role='free'
            )
            
            return {"access_token": access_token, "token_type": "bearer"}

@router.post("/login", response_model=Token)
async def login(user: UserLogin, request: Request):
    if USE_POSTGRES:
        with get_pg_connection() as conn:
            cursor = conn.cursor()
            
            try:
                cursor.execute("""
                    SELECT id, username, email, role, password_hash FROM users 
                    WHERE username = %s
                """, (user.username,))
                
                db_user = cursor.fetchone()
                
                if not db_user:
                    raise HTTPException(status_code=401, detail="Invalid credentials")
                
                try:
                    ph.verify(db_user[4], user.password)
                except VerifyMismatchError:
                    raise HTTPException(status_code=401, detail="Invalid credentials")
                
                # Update last login
                cursor.execute("UPDATE users SET last_login = NOW() WHERE id = %s",
                              (db_user[0],))
                
                access_token = create_access_token(
                    user_id=db_user[0],
                    username=db_user[1],
                    role=db_user[3]
                )
                
                return {"access_token": access_token, "token_type": "bearer"}
            finally:
                cursor.close()
    else:
        # SQLite fallback
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, username, email, role, password_hash FROM users 
                WHERE username = ?
            """, (user.username,))
            
            db_user = cursor.fetchone()
            
            if not db_user:
                raise HTTPException(status_code=401, detail="Invalid credentials")
            
            try:
                ph.verify(db_user[4], user.password)
            except VerifyMismatchError:
                raise HTTPException(status_code=401, detail="Invalid credentials")
            
            # Update last login
            cursor.execute("UPDATE users SET last_login = ? WHERE id = ?",
                          (datetime.now(), db_user[0]))
            conn.commit()
            
            access_token = create_access_token(
                user_id=db_user[0],
                username=db_user[1],
                role=db_user[3]
            )
            
            return {"access_token": access_token, "token_type": "bearer"}

@router.get("/me", response_model=dict)
async def get_current_user(user_data: dict = Depends(verify_token)):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, username, email, role, created_at FROM users 
            WHERE id = ?
        """, (user_data['user_id'],))
        
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {
            "id": user[0],
            "username": user[1],
            "email": user[2],
            "role": user[3],
            "created_at": user[4]
        }

@router.get("/usage")
async def get_usage(user_data: dict = Depends(verify_token)):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM scan_results 
            WHERE user_id = ? AND strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')
        """, (user_data['user_id'],))
        
        monthly_scans = cursor.fetchone()[0]
        
        limit = 999 if user_data['role'] == 'pro' else 5
        
        return {
            "scans": monthly_scans,
            "limit": limit,
            "role": user_data['role']
        }
