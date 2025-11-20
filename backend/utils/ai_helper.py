"""
AI Helper Utility for CVE and Security Analysis
"""
import os
import ssl

# Disable SSL verification for litellm to prevent certificate loading hangs
os.environ['SSL_VERIFY'] = 'false'
os.environ['HTTPX_SSL_VERIFY'] = 'false'

# Create unverified SSL context globally
try:
    ssl._create_default_https_context = ssl._create_unverified_context
except AttributeError:
    pass

from litellm import acompletion

async def generate_ai_response(prompt: str, user_id: int, model: str = "gpt-4o-mini") -> str:
    """Generate AI response using LiteLLM"""
    try:
        response = await acompletion(
            model=model,
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert assistant specializing in CVE analysis and vulnerability assessment."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=500
        )
        
        return response.choices[0].message.content.strip()
    
    except Exception as e:
        # Fallback to basic keyword extraction if AI fails
        return extract_keywords_fallback(prompt)

def extract_keywords_fallback(query: str) -> str:
    """Fallback keyword extraction without AI"""
    # Remove common words
    stop_words = {'cve', 'for', 'the', 'a', 'an', 'and', 'or', 'in', 'on', 'at', 'to', 'from', 'with', 'vulnerability', 'vulnerabilities', 'security'}
    
    words = query.lower().split()
    keywords = [w for w in words if w not in stop_words and len(w) > 2]
    
    return ' '.join(keywords)
