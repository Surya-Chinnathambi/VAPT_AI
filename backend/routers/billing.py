from fastapi import APIRouter, HTTPException, Depends
import stripe
import os
from datetime import datetime
from psycopg2.extras import RealDictCursor

from routers.auth import verify_token
from database.connection import get_db_connection, get_user_monthly_usage

router = APIRouter()

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

PRICING_PLANS = {
    "free": {
        "name": "Free Tier",
        "price": 0,
        "scans_per_month": 5
    },
    "pro": {
        "name": "Professional",
        "price": 29.99,
        "scans_per_month": 999999
    },
    "enterprise": {
        "name": "Enterprise",
        "price": 99.99,
        "scans_per_month": 999999
    }
}

@router.get("/plans")
async def get_plans():
    return {"plans": PRICING_PLANS}

@router.get("/subscription")
async def get_subscription(user_data: dict = Depends(verify_token)):
    current_plan = user_data.get('role', 'free')
    
    # Get monthly usage
    monthly_scans = get_user_monthly_usage(user_data['user_id'])
    
    # Get total counts
    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("SELECT COUNT(*) as count FROM scans WHERE user_id = %s", 
                      (user_data['user_id'],))
        total_scans = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM reports WHERE user_id = %s", 
                      (user_data['user_id'],))
        total_reports = cursor.fetchone()['count']
        cursor.close()
    
    plan_info = PRICING_PLANS.get(current_plan, PRICING_PLANS['free'])
    
    return {
        "current_plan": current_plan,
        "plan_info": plan_info,
        "usage": {
            "monthly_scans": monthly_scans,
            "total_scans": total_scans,
            "total_reports": total_reports
        }
    }

@router.post("/create-checkout")
async def create_checkout_session(
    plan: str,
    user_data: dict = Depends(verify_token)
):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Stripe not configured")
    
    if plan not in PRICING_PLANS or plan == "free":
        raise HTTPException(status_code=400, detail="Invalid plan")
    
    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT email FROM users WHERE id = %s", (user_data['user_id'],))
        user_email = cursor.fetchone()['email']
        cursor.close()
    
    try:
        session = stripe.checkout.Session.create(
            customer_email=user_email,
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': PRICING_PLANS[plan]['name'],
                    },
                    'unit_amount': int(PRICING_PLANS[plan]['price'] * 100),
                    'recurring': {
                        'interval': 'month',
                    },
                },
                'quantity': 1,
            }],
            mode='subscription',
            success_url=f"{os.getenv('FRONTEND_URL', 'http://localhost:3000')}/billing?success=true",
            cancel_url=f"{os.getenv('FRONTEND_URL', 'http://localhost:3000')}/billing?canceled=true",
        )
        
        return {"checkout_url": session.url}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Checkout creation failed: {str(e)}")
