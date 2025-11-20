from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from typing import List, Optional
import os
import requests
import json
import redis
import uuid
from datetime import datetime

from routers.auth import verify_token
from core.rate_limiting import limiter, ai_chat_limit
from database.connection import get_db_cursor

router = APIRouter()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT", "https://litellm.dev.asoclab.dev/v1")
AZURE_OPENAI_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT", "azure/gpt-5-chat")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6380/0")

# Redis connection for conversation caching
try:
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    redis_client.ping()
    REDIS_AVAILABLE = True
    print(f"✅ Redis connected for conversation caching")
except Exception as e:
    REDIS_AVAILABLE = False
    print(f"⚠️ Redis not available: {e}")

# Check if OpenAI is configured
OPENAI_AVAILABLE = bool(OPENAI_API_KEY)
if OPENAI_AVAILABLE:
    print(f"✅ OpenAI/LiteLLM configured with endpoint: {AZURE_OPENAI_ENDPOINT}")
    print(f"✅ Using model: {AZURE_OPENAI_DEPLOYMENT}")
else:
    print("⚠️ OpenAI API key not configured")

def call_openai_api(messages: list, model: str = None, max_tokens: int = 2000) -> str:
    """
    Call OpenAI/LiteLLM API directly using requests (Python 3.14 compatible)
    """
    if not OPENAI_API_KEY:
        raise ValueError("OpenAI API key not configured")
    
    # Use Azure deployment model if not specified
    if model is None:
        model = AZURE_OPENAI_DEPLOYMENT
    
    url = f"{AZURE_OPENAI_ENDPOINT}/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens
    }
    
    response = requests.post(url, headers=headers, json=payload, timeout=60)
    response.raise_for_status()
    
    data = response.json()
    return data["choices"][0]["message"]["content"]

SECURITY_SYSTEM_PROMPT = """
You are an expert cybersecurity AI assistant specializing in:
- Network security analysis and threat assessment
- Vulnerability identification and remediation
- Penetration testing methodologies and best practices
- CVE analysis and risk evaluation
- Security compliance frameworks (OWASP, PCI-DSS, HIPAA)
- Incident response and forensics
- Security architecture and defense strategies

Provide detailed, actionable security advice. When discussing vulnerabilities:
1. Explain the technical details clearly
2. Assess the risk level and potential impact
3. Provide specific remediation steps
4. Reference relevant compliance frameworks
5. Suggest additional security measures

Always prioritize ethical security practices and responsible disclosure.
"""

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    message: str
    context: Optional[str] = None
    history: Optional[List[ChatMessage]] = []
    session_id: Optional[str] = None

class AnalyzeRequest(BaseModel):
    scan_type: str
    results: dict

class ConversationHistoryResponse(BaseModel):
    session_id: str
    messages: List[ChatMessage]
    created_at: str
    message_count: int

# Helper functions for conversation management
def get_or_create_conversation(user_id: int, session_id: str = None) -> tuple:
    """Get existing conversation or create new one. Returns (conversation_id, session_id)"""
    with get_db_cursor() as cursor:
        if session_id:
            # Try to find existing conversation
            cursor.execute(
                "SELECT id, session_id FROM chat_conversations WHERE session_id = %s AND user_id = %s",
                (session_id, user_id)
            )
            result = cursor.fetchone()
            if result:
                return result['id'], result['session_id']
        
        # Create new conversation
        new_session_id = session_id or str(uuid.uuid4())
        cursor.execute(
            """
            INSERT INTO chat_conversations (user_id, session_id, created_at, updated_at, last_message_at, is_active)
            VALUES (%s, %s, %s, %s, %s, TRUE)
            RETURNING id, session_id
            """,
            (user_id, new_session_id, datetime.utcnow(), datetime.utcnow(), datetime.utcnow())
        )
        result = cursor.fetchone()
        return result['id'], result['session_id']

def save_message_to_db(conversation_id: int, role: str, content: str, metadata: dict = None):
    """Save a message to the database"""
    with get_db_cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO chat_messages (conversation_id, role, content, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (conversation_id, role, content, json.dumps(metadata) if metadata else None, datetime.utcnow())
        )
        
        # Update conversation metadata
        cursor.execute(
            """
            UPDATE chat_conversations 
            SET message_count = message_count + 1,
                last_message_at = %s,
                updated_at = %s
            WHERE id = %s
            """,
            (datetime.utcnow(), datetime.utcnow(), conversation_id)
        )

def get_conversation_history(conversation_id: int, limit: int = 20) -> List[dict]:
    """Get conversation history from database"""
    with get_db_cursor() as cursor:
        cursor.execute(
            """
            SELECT role, content, created_at
            FROM chat_messages
            WHERE conversation_id = %s
            ORDER BY created_at ASC
            LIMIT %s
            """,
            (conversation_id, limit)
        )
        return cursor.fetchall()

def cache_conversation_in_redis(session_id: str, messages: List[dict]):
    """Cache conversation in Redis for fast access"""
    if not REDIS_AVAILABLE:
        return
    
    try:
        # Convert datetime objects to strings for JSON serialization
        serializable_messages = []
        for msg in messages:
            msg_copy = dict(msg)
            if 'created_at' in msg_copy and msg_copy['created_at']:
                msg_copy['created_at'] = str(msg_copy['created_at'])
            serializable_messages.append(msg_copy)
        
        # Store in Redis with 1 hour expiration
        key = f"conversation:{session_id}"
        redis_client.setex(key, 3600, json.dumps(serializable_messages))
        print(f"✅ Cached conversation {session_id} in Redis")
    except Exception as e:
        print(f"⚠️ Redis cache error: {e}")

def get_conversation_from_redis(session_id: str) -> Optional[List[dict]]:
    """Get conversation from Redis cache"""
    if not REDIS_AVAILABLE:
        return None
    
    try:
        key = f"conversation:{session_id}"
        cached = redis_client.get(key)
        if cached:
            return json.loads(cached)
    except Exception as e:
        print(f"Redis retrieve error: {e}")
    
    return None

@router.post("/message")
async def chat_message(
    request: ChatRequest,
    user_data: dict = Depends(verify_token),
    http_request: Request = None
):
    if not OPENAI_AVAILABLE:
        raise HTTPException(status_code=503, detail="OpenAI API not configured")
    
    try:
        user_id = user_data["user_id"]
        
        # Get or create conversation
        conversation_id, session_id = get_or_create_conversation(user_id, request.session_id)
        
        # Try to get history from Redis cache first, then database
        cached_history = get_conversation_from_redis(session_id)
        if cached_history:
            db_history = cached_history
        else:
            db_history = get_conversation_history(conversation_id, limit=20)
            if db_history:
                cache_conversation_in_redis(session_id, db_history)
        
        # Build messages for OpenAI
        messages = [{"role": "system", "content": SECURITY_SYSTEM_PROMPT}]
        
        if request.context:
            messages.append({"role": "user", "content": f"Context: {request.context}"})
        
        # Add database history
        for msg in db_history[-10:]:  # Last 10 messages
            messages.append({"role": msg["role"], "content": msg["content"]})
        
        # Add new user message
        messages.append({"role": "user", "content": request.message})
        
        # Save user message to database
        save_message_to_db(conversation_id, "user", request.message)
        
        # Call OpenAI/LiteLLM API
        response_content = call_openai_api(messages, max_tokens=2000)
        
        # Save assistant response to database
        save_message_to_db(conversation_id, "assistant", response_content)
        
        # Update Redis cache
        updated_history = get_conversation_history(conversation_id, limit=20)
        cache_conversation_in_redis(session_id, updated_history)
        
        return {
            "message": response_content,
            "role": "assistant",
            "session_id": session_id
        }
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"OpenAI API error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat error: {str(e)}")

@router.post("/analyze")
async def analyze_scan(
    request: AnalyzeRequest,
    user_data: dict = Depends(verify_token),
    http_request: Request = None
):
    if not OPENAI_AVAILABLE:
        raise HTTPException(status_code=503, detail="OpenAI API not configured")
    
    try:
        context_prompt = f"""
        Analyze these {request.scan_type} scan results and provide:
        1. Risk assessment and severity levels
        2. Detailed vulnerability explanations
        3. Specific remediation steps
        4. Compliance framework mapping
        5. Additional security recommendations
        
        Scan Results:
        {json.dumps(request.results, indent=2)}
        """
        
        messages = [
            {"role": "system", "content": SECURITY_SYSTEM_PROMPT},
            {"role": "user", "content": context_prompt}
        ]
        
        # Call OpenAI/LiteLLM API directly with Azure deployment
        analysis = call_openai_api(messages, max_tokens=3000)
        
        return {
            "analysis": analysis,
            "scan_type": request.scan_type
        }
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"OpenAI API error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")

@router.get("/conversations")
async def get_user_conversations(
    user_data: dict = Depends(verify_token),
    limit: int = 10
):
    """Get list of user's conversations"""
    try:
        user_id = user_data["user_id"]
        
        with get_db_cursor() as cursor:
            cursor.execute(
                """
                SELECT 
                    session_id,
                    title,
                    created_at,
                    updated_at,
                    last_message_at,
                    message_count,
                    is_active
                FROM chat_conversations
                WHERE user_id = %s AND is_active = TRUE
                ORDER BY last_message_at DESC
                LIMIT %s
                """,
                (user_id, limit)
            )
            conversations = cursor.fetchall()
            
        return {
            "conversations": conversations,
            "total": len(conversations)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching conversations: {str(e)}")

@router.get("/conversation/{session_id}")
async def get_conversation_by_session(
    session_id: str,
    user_data: dict = Depends(verify_token)
):
    """Get full conversation history by session ID"""
    try:
        user_id = user_data["user_id"]
        
        # Verify ownership
        with get_db_cursor() as cursor:
            cursor.execute(
                "SELECT id FROM chat_conversations WHERE session_id = %s AND user_id = %s",
                (session_id, user_id)
            )
            result = cursor.fetchone()
            
            if not result:
                raise HTTPException(status_code=404, detail="Conversation not found")
            
            conversation_id = result['id']
        
        # Try Redis cache first
        cached_messages = get_conversation_from_redis(session_id)
        if cached_messages:
            messages = cached_messages
        else:
            messages = get_conversation_history(conversation_id, limit=100)
            cache_conversation_in_redis(session_id, messages)
        
        return {
            "session_id": session_id,
            "messages": [{"role": m["role"], "content": m["content"]} for m in messages],
            "message_count": len(messages)
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching conversation: {str(e)}")

@router.delete("/conversation/{session_id}")
async def delete_conversation(
    session_id: str,
    user_data: dict = Depends(verify_token)
):
    """Delete/archive a conversation"""
    try:
        user_id = user_data["user_id"]
        
        with get_db_cursor() as cursor:
            cursor.execute(
                """
                UPDATE chat_conversations 
                SET is_active = FALSE, updated_at = %s
                WHERE session_id = %s AND user_id = %s
                """,
                (datetime.utcnow(), session_id, user_id)
            )
            
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Conversation not found")
        
        # Remove from Redis cache
        if REDIS_AVAILABLE:
            try:
                redis_client.delete(f"conversation:{session_id}")
            except:
                pass
        
        return {"message": "Conversation deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting conversation: {str(e)}")

