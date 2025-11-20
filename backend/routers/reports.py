from fastapi import APIRouter, HTTPException, Depends, Response
import os
from typing import List

from routers.auth import verify_token
from services.report_service import generate_security_report
from utils.database import get_db_connection

router = APIRouter()

@router.post("/generate")
async def generate_report(
    report_name: str = "Security Assessment",
    user_data: dict = Depends(verify_token)
):
    try:
        filename = generate_security_report(user_data['user_id'], report_name)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO reports (user_id, report_name, report_type, file_path)
                VALUES (?, ?, 'security_assessment', ?)
            """, (user_data['user_id'], report_name, filename))
            report_id = cursor.lastrowid
            conn.commit()
        
        return {
            "success": True,
            "report_id": report_id,
            "filename": filename
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

@router.get("/list")
async def list_reports(user_data: dict = Depends(verify_token)):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM reports 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        """, (user_data['user_id'],))
        
        reports = cursor.fetchall()
        return {"reports": [dict(report) for report in reports]}

@router.get("/download/{report_id}")
async def download_report(
    report_id: int,
    user_data: dict = Depends(verify_token)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT file_path FROM reports 
            WHERE id = ? AND user_id = ?
        """, (report_id, user_data['user_id']))
        
        result = cursor.fetchone()
        
        if not result:
            raise HTTPException(status_code=404, detail="Report not found")
        
        file_path = result[0]
        
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="Report file not found")
        
        with open(file_path, 'rb') as f:
            content = f.read()
        
        return Response(
            content=content,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={os.path.basename(file_path)}"}
        )
