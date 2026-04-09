"""
SDU AI Agent — Core Logic
Uses Groq LLM with tool-calling pattern.

The agent:
1. Receives user message + student_id
2. Detects intent
3. Calls appropriate backend tools
4. Formats response using LLM
"""

import json
import os
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, date, timedelta
from dotenv import load_dotenv

from groq import AsyncGroq

logger = logging.getLogger(__name__)
load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

# ============================================================
# Tool definitions for the LLM
# ============================================================

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_assignments",
            "description": "Get assignments and deadlines for the student. Use when student asks about homework, assignments, deadlines, or tasks due.",
            "parameters": {
                "type": "object",
                "properties": {
                    "days": {
                        "type": "integer",
                        "description": "Number of days ahead to look for assignments. Use 7 for 'this week', 1 for 'tomorrow', 30 for 'this month'. Default is 30.",
                        "default": 30
                    },
                    "include_submitted": {
                        "type": "boolean",
                        "description": "Whether to include already submitted assignments",
                        "default": False
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_next_class",
            "description": "Get information about the student's next upcoming class. Use when student asks 'what class do I have next', 'where is my next lecture', 'when is my next class'.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_schedule_today",
            "description": "Get the student's schedule for TODAY only. Use ONLY when student asks about today's classes.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_schedule_tomorrow",
            "description": "Get the student's schedule for TOMORROW. Use when student asks about tomorrow's classes or занятия на завтра.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_schedule_by_day",
            "description": "Get schedule for a specific day of the week or date. Use when student mentions a specific weekday (Monday/Tuesday/Wednesday/Thursday/Friday, or Понедельник/Вторник/Среда/Четверг/Пятница) or a specific date like '21 февраля' or '2026-03-10'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "day": {
                        "type": "string",
                        "description": "Day name in English (Monday, Tuesday, Wednesday, Thursday, Friday) or a date string like '2026-03-10'. Convert Russian day names to English."
                    }
                },
                "required": ["day"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_attendance",
            "description": "Get attendance statistics for the student's courses. Use when student asks about attendance, absences, or how many classes they've missed.",
            "parameters": {
                "type": "object",
                "properties": {
                    "course_code": {
                        "type": "string",
                        "description": "Optional: specific course code to check attendance for"
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_deadlines",
            "description": "Get upcoming deadlines sorted by urgency. Use when student asks 'what are my deadlines', 'what's due soon', 'urgent tasks'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "days": {
                        "type": "integer",
                        "description": "Days ahead to look for deadlines",
                        "default": 7
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_full_schedule",
            "description": "Get the student's weekly schedule (all days). Use when student asks for their full timetable or weekly schedule.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    }
]

SYSTEM_PROMPT = """You are SDU AI Assistant — a helpful academic assistant for students at Suleyman Demirel University (SDU) in Kazakhstan.

Your role:
- Answer questions about assignments, schedule, deadlines, and attendance
- Always use the provided tools to get real data — NEVER make up information
- Respond in the same language the student uses (Russian, Kazakh, or English)
- Be friendly, concise, and helpful
- If you need data, call the appropriate tool first

Important rules:
- NEVER hallucinate course names, deadlines, or room numbers
- Always call a tool if the question requires real student data
- Format responses clearly with relevant details
- For Russian/Kazakh queries, respond in that language

Current date and time: {current_datetime}
Student ID: {student_id}
"""


class SDUAgent:
    def __init__(self, data_service):
        self.data_service = data_service
        if GROQ_API_KEY:
            self.client = AsyncGroq(api_key=GROQ_API_KEY)
        else:
            self.client = None
            logger.warning("GROQ_API_KEY not set — AI responses will be disabled")

    async def process_message(
        self,
        message: str,
        student_id: str,
        chat_history: List[Dict] = []
    ) -> Dict[str, Any]:
        """
        Main entry point for processing a student message.
        Returns: { response: str, tool_used: str | None, data: dict | None }
        """
        if not self.client:
            return {
                "response": "AI service is not configured. Please set GROQ_API_KEY.",
                "tool_used": None,
                "data": None
            }

        now = datetime.now()
        system = SYSTEM_PROMPT.format(
            current_datetime=now.strftime("%A, %Y-%m-%d %H:%M"),
            student_id=student_id
        )

        messages = [{"role": "system", "content": system}]

        # Add recent chat history (last 6 messages for context)
        for h in chat_history[-6:]:
            messages.append({"role": h["role"], "content": h["message"]})

        messages.append({"role": "user", "content": message})

        tool_used = None
        tool_data = None

        # First LLM call — may request tool use
        response = await self.client.chat.completions.create(
            model=GROQ_MODEL,
            messages=messages,
            tools=TOOLS,
            tool_choice="auto",
            max_tokens=1024,
            temperature=0.3,
        )

        response_message = response.choices[0].message

        # Handle tool calls
        if response_message.tool_calls:
            tool_call = response_message.tool_calls[0]
            tool_name = tool_call.function.name
            tool_args = json.loads(tool_call.function.arguments or "{}")

            logger.info(f"Agent calling tool: {tool_name} with args: {tool_args}")
            tool_used = tool_name

            # Execute the tool
            tool_result = await self._execute_tool(tool_name, tool_args, student_id)
            tool_data = tool_result

            # Add tool call + result to messages
            messages.append({
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": tool_call.id,
                        "type": "function",
                        "function": {
                            "name": tool_name,
                            "arguments": tool_call.function.arguments
                        }
                    }
                ]
            })
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": json.dumps(tool_result, ensure_ascii=False, default=str)
            })

            # Second LLM call — generate human-readable response
            final_response = await self.client.chat.completions.create(
                model=GROQ_MODEL,
                messages=messages,
                max_tokens=512,
                temperature=0.4,
            )
            answer = final_response.choices[0].message.content

        else:
            # No tool needed — direct answer
            answer = response_message.content

        return {
            "response": answer,
            "tool_used": tool_used,
            "data": tool_data
        }

    async def _execute_tool(self, tool_name: str, args: Dict, student_id: str) -> Any:
        """Execute a tool and return its result."""
        try:
            if tool_name == "get_assignments":
                return await self.data_service.get_assignments(
                    student_id,
                    days=args.get("days", 30),
                    include_submitted=args.get("include_submitted", False),
                )
            elif tool_name == "get_next_class":
                return await self.data_service.get_next_class(student_id)
            elif tool_name == "get_schedule_today":
                return await self.data_service.get_schedule_for_day(student_id, day=None)
            elif tool_name == "get_schedule_tomorrow":
                from datetime import timedelta as td
                tomorrow = (__import__("datetime").datetime.now() + td(days=1)).strftime("%A")
                return await self.data_service.get_schedule_for_day(student_id, day=tomorrow)
            elif tool_name == "get_schedule_by_day":
                return await self.data_service.get_schedule_for_day(student_id, day=args.get("day"))
            elif tool_name == "get_attendance":
                return await self.data_service.get_attendance(
                    student_id,
                    course_code=args.get("course_code"),
                )
            elif tool_name == "get_deadlines":
                return await self.data_service.get_assignments(
                    student_id,
                    days=args.get("days", 7),
                    include_submitted=False,
                )
            elif tool_name == "get_full_schedule":
                return await self.data_service.get_full_schedule(student_id)
            else:
                return {"error": f"Unknown tool: {tool_name}"}
        except Exception as e:
            logger.error(f"Tool execution error ({tool_name}): {e}")
            return {"error": str(e)}
