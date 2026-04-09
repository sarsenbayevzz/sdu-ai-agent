from fastapi import APIRouter, Query, Header
from typing import Optional
from app.agent.data_service import DataService, PORTAL_SESSIONS
from app.api.auth import get_current_student

router = APIRouter()


def extract_moodle_token(authorization: Optional[str]) -> str:
    if not authorization:
        return ""
    try:
        data = get_current_student(authorization)
        return data.get("moodle_token", "")
    except Exception:
        return ""


@router.get("/")
async def get_attendance(
    student_id: str = Query(...),
    course_code: Optional[str] = Query(None),
    authorization: Optional[str] = Header(None),
):
    moodle_token = extract_moodle_token(authorization)
    portal = PORTAL_SESSIONS.get(student_id)
    ds = DataService(moodle_token=moodle_token, portal_client=portal)
    return await ds.get_attendance(student_id, course_code=course_code)
