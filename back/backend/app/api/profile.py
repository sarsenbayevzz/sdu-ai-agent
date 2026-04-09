from fastapi import APIRouter, Query, Header
from typing import Optional
from app.api.auth import get_current_student
from app.integrations.sdu_portal import SDUPortalClient
import os

router = APIRouter()
USE_MOCK = os.getenv("USE_MOCK_DATA", "true").lower() == "true"


@router.get("/")
async def get_profile(
    student_id: str = Query(...),
    password: str = Query(...),
    authorization: Optional[str] = Header(None),
):
    """
    Get full student profile from my.sdu.edu.kz.
    Requires student password to login to portal.
    """
    if USE_MOCK:
        return {
            "student_id": student_id,
            "fullname": "Azhar Bekova",
            "fullname_native": "Азхар Бекова",
            "program": "Computer Science - 3",
            "advisor": "Dr. Smith",
            "status": "Studying",
            "grant_type": "SG [State Grant]",
            "email": "a.bekova@sdu.edu.kz",
            "birth_date": "01-JAN-03",
            "photo_url": "",
        }

    client = SDUPortalClient(student_id, password)
    try:
        logged_in = await client.login()
        if not logged_in:
            return {"error": "Portal login failed"}
        profile = await client.get_profile()
        return profile or {"error": "Could not scrape profile"}
    finally:
        await client.close()
