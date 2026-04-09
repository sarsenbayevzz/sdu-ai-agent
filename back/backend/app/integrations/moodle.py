"""
Moodle API Integration for SDU
Docs: https://docs.moodle.org/dev/Web_service_API_functions

To get your Moodle token:
1. Login to moodle.sdu.edu.kz
2. Go to: User menu → Preferences → Security keys
3. Copy the "Mobile web service" token

Or via REST:
POST https://moodle.sdu.edu.kz/login/token.php
Body: username=YOUR_ID&password=YOUR_PASS&service=moodle_mobile_app
"""

import httpx
import os
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

MOODLE_BASE_URL = os.getenv("MOODLE_URL", "https://moodle.sdu.edu.kz")
MOODLE_API_PATH = "/webservice/rest/server.php"


class MoodleClient:
    def __init__(self, token: str, base_url: str = MOODLE_BASE_URL):
        self.token = token
        self.base_url = base_url
        self.api_url = f"{base_url}{MOODLE_API_PATH}"

    async def call(self, function: str, params: Dict = {}) -> Any:
        """Call a Moodle Web Service function."""
        payload = {
            "wstoken": self.token,
            "wsfunction": function,
            "moodlewsrestformat": "json",
            **params
        }
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            try:
                response = await client.post(self.api_url, data=payload)
                response.raise_for_status()
                data = response.json()
                if isinstance(data, dict) and "exception" in data:
                    raise Exception(f"Moodle error: {data.get('message', 'Unknown error')}")
                return data
            except httpx.RequestError as e:
                logger.error(f"Moodle request error: {e}")
                raise

    async def get_enrolled_courses(self) -> List[Dict]:
        """Get courses the student is enrolled in."""
        result = await self.call(
            "core_enrol_get_users_courses",
            {"userid": await self.get_userid()}
        )
        return result or []

    async def get_userid(self) -> int:
        """Get current user ID from token."""
        result = await self.call("core_webservice_get_site_info")
        return result.get("userid")

    async def get_assignments(self, course_ids: List[int]) -> List[Dict]:
        """Get assignments for given course IDs."""
        params = {}
        for i, cid in enumerate(course_ids):
            params[f"courseids[{i}]"] = cid

        result = await self.call("mod_assign_get_assignments", params)
        assignments = []

        for course in result.get("courses", []):
            course_name = course.get("fullname", "")
            for assign in course.get("assignments", []):
                assignments.append({
                    "id": assign.get("id"),
                    "course_name": course_name,
                    "title": assign.get("name"),
                    "deadline": datetime.fromtimestamp(assign.get("duedate", 0)),
                    "submitted": False,  # check separately
                    "moodle_assign_id": assign.get("id"),
                })

        return assignments

    async def get_submission_status(self, assign_id: int) -> bool:
        """Check if student submitted a specific assignment."""
        result = await self.call(
            "mod_assign_get_submission_status",
            {"assignid": assign_id}
        )
        submission = result.get("lastattempt", {}).get("submission", {})
        return submission.get("status") == "submitted"


async def get_moodle_token(student_id: str, password: str) -> Optional[str]:
    """
    Authenticate with Moodle and get token.
    Returns None if authentication fails.
    """
    url = f"{MOODLE_BASE_URL}/login/token.php"
    params = {
        "username": student_id,
        "password": password,
        "service": "moodle_mobile_app"
    }
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        try:
            response = await client.post(url, data=params)
            data = response.json()
            if "token" in data:
                return data["token"]
            logger.warning(f"Moodle auth failed: {data.get('error', 'Unknown')}")
            return None
        except Exception as e:
            logger.error(f"Moodle token error: {e}")
            return None
