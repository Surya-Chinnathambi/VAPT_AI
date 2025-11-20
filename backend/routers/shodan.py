from fastapi import APIRouter, HTTPException, Depends
import requests
import os

from routers.auth import verify_token

router = APIRouter()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
SHODAN_BASE_URL = "https://api.shodan.io"

@router.get("/search")
async def search_shodan(
    query: str,
    limit: int = 100,
    user_data: dict = Depends(verify_token)
):
    if not SHODAN_API_KEY:
        raise HTTPException(status_code=503, detail="Shodan API key not configured")
    
    try:
        # Clean query - extract domain/IP if URL provided
        import re
        from urllib.parse import urlparse
        
        # If it's a URL, extract domain
        if query.startswith('http://') or query.startswith('https://'):
            parsed = urlparse(query)
            query = parsed.netloc or parsed.path
        
        # Remove www. prefix
        query = query.replace('www.', '')
        
        url = f"{SHODAN_BASE_URL}/shodan/host/search"
        params = {
            'key': SHODAN_API_KEY,
            'query': query,
            'facets': '',  # Empty facets
            'minify': False
        }
        
        response = requests.get(url, params=params, timeout=30)
        
        if response.status_code == 403:
            # API key might have limited access
            raise HTTPException(
                status_code=403,
                detail="Shodan API access denied. Your API key may need upgrading or may have reached its limit."
            )
        
        response.raise_for_status()
        data = response.json()
        
        # Limit results
        if 'matches' in data:
            data['matches'] = data['matches'][:limit]
        
        return data
    
    except HTTPException:
        raise
    except requests.exceptions.Timeout:
        raise HTTPException(status_code=504, detail="Shodan API request timed out. Please try again.")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            raise HTTPException(status_code=503, detail="Invalid Shodan API key. Please check your configuration.")
        raise HTTPException(status_code=500, detail=f"Shodan API error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Shodan search failed: {str(e)}")

@router.get("/host/{ip}")
async def get_host_info(
    ip: str,
    user_data: dict = Depends(verify_token)
):
    if not SHODAN_API_KEY:
        raise HTTPException(status_code=503, detail="Shodan API key not configured")
    
    try:
        url = f"{SHODAN_BASE_URL}/shodan/host/{ip}"
        params = {'key': SHODAN_API_KEY}
        
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        
        return response.json()
    
    except requests.exceptions.Timeout:
        raise HTTPException(status_code=504, detail="Shodan host lookup timed out")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            raise HTTPException(status_code=404, detail="Host not found in Shodan database")
        raise HTTPException(status_code=500, detail=f"Host lookup failed: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Host lookup failed: {str(e)}")

@router.get("/api-info")
async def get_api_info(user_data: dict = Depends(verify_token)):
    if not SHODAN_API_KEY:
        return {"status": "not_configured"}
    
    try:
        url = f"{SHODAN_BASE_URL}/api-info"
        params = {'key': SHODAN_API_KEY}
        
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        
        return response.json()
    
    except Exception as e:
        return {"status": "error", "message": str(e)}
