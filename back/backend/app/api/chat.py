from fastapi import APIRouter, HTTPException, Header
from app.schemas.schemas import ChatRequest, ChatResponse
from app.agent.agent import SDUAgent
from app.agent.data_service import DataService
from app.api.auth import get_current_student
from typing import Optional
import logging

router = APIRouter()
logger = logging.getLogger(__name__)


def extract_moodle_token(authorization: Optional[str]) -> str:
    if not authorization:
        return ""
    try:
        data = get_current_student(authorization)
        return data.get("moodle_token", "")
    except Exception:
        return ""


@router.post("/", response_model=ChatResponse)
async def chat(request: ChatRequest, authorization: Optional[str] = Header(None)):
    if not request.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    moodle_token = extract_moodle_token(authorization)
    ds = DataService(moodle_token=moodle_token)
    agent = SDUAgent(ds)

    try:
        history = await ds.get_chat_history(request.student_id)
        result = await agent.process_message(
            message=request.message,
            student_id=request.student_id,
            chat_history=history,
        )
        await ds.save_chat_message(request.student_id, "user", request.message)
        await ds.save_chat_message(request.student_id, "assistant", result["response"])

        return ChatResponse(
            response=result["response"],
            tool_used=result.get("tool_used"),
            data=result.get("data")
        )
    except Exception as e:
        logger.error(f"Chat error: {e}")
        raise HTTPException(status_code=500, detail=f"Agent error: {str(e)}")


@router.get("/history/{student_id}")
async def get_history(student_id: str, limit: int = 20):
    ds = DataService()
    history = await ds.get_chat_history(student_id, limit=limit)
    return {"student_id": student_id, "messages": history}
