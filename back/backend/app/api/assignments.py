from fastapi import APIRouter, Query, Header
from typing import Optional
from app.agent.data_service import DataService
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
async def get_assignments(
    student_id: str = Query(...),
    days: int = Query(30),
    include_submitted: bool = Query(False),
    authorization: Optional[str] = Header(None),
):
    moodle_token = extract_moodle_token(authorization)
    ds = DataService(moodle_token=moodle_token)
    return await ds.get_assignments(student_id, days=days, include_submitted=include_submitted)


@router.get("/upcoming")
async def get_upcoming_assignments(
    student_id: str = Query(...),
    days: int = Query(7),
    authorization: Optional[str] = Header(None),
):
    moodle_token = extract_moodle_token(authorization)
    ds = DataService(moodle_token=moodle_token)
    return await ds.get_assignments(student_id, days=days)
