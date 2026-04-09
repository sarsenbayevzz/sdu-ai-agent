from fastapi import APIRouter, Query, Header
from typing import Optional
from app.agent.data_service import DataService, PORTAL_SESSIONS

router = APIRouter()


def get_ds(student_id: str) -> DataService:
    portal = PORTAL_SESSIONS.get(student_id)
    return DataService(portal_client=portal)


@router.get("/today")
async def get_schedule_today(student_id: str = Query(...)):
    return await get_ds(student_id).get_schedule_for_day(student_id)


@router.get("/next")
async def get_next_class(student_id: str = Query(...)):
    return await get_ds(student_id).get_next_class(student_id)


@router.get("/week")
async def get_weekly_schedule(student_id: str = Query(...)):
    return await get_ds(student_id).get_full_schedule(student_id)


@router.get("/day")
async def get_schedule_for_day(
    student_id: str = Query(...),
    day: Optional[str] = Query(None),
):
    return await get_ds(student_id).get_schedule_for_day(student_id, day=day)
