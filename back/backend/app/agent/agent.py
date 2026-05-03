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
        chat_history: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """
        Main entry point for processing a student message.
        Returns: { response: str, tool_used: str | None, data: dict | None }
        """
        message = (message or "").strip()
        chat_history = chat_history or []
        if not message:
            return {
                "response": "Ask a question about schedule, assignments, deadlines, or attendance.",
                "tool_used": None,
                "data": None
            }

        if not self.client:
            return await self._rule_based_response(message, student_id)

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

        try:
            # First LLM call — may request tool use
            response = await self.client.chat.completions.create(
                model=GROQ_MODEL,
                messages=messages,
                tools=TOOLS,
                tool_choice="auto",
                max_tokens=1024,
                temperature=0.3,
            )
        except Exception as e:
            logger.error(f"Groq first call error: {e}")
            fallback = await self._rule_based_response(message, student_id)
            fallback["response"] = f"{fallback['response']}\n\nAI is temporarily unavailable, so I answered using app data."
            return fallback

        response_message = response.choices[0].message

        # Handle tool calls
        if response_message.tool_calls:
            tool_results = []
            tool_names = []
            messages.append({
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": call.id,
                        "type": "function",
                        "function": {
                            "name": call.function.name,
                            "arguments": call.function.arguments,
                        }
                    }
                    for call in response_message.tool_calls
                ]
            })

            for tool_call in response_message.tool_calls:
                tool_name = tool_call.function.name
                try:
                    tool_args = json.loads(tool_call.function.arguments or "{}")
                except json.JSONDecodeError:
                    tool_args = {}

                logger.info(f"Agent calling tool: {tool_name} with args: {tool_args}")
                tool_names.append(tool_name)

                tool_result = await self._execute_tool(tool_name, tool_args, student_id)
                tool_results.append({"tool": tool_name, "data": tool_result})

                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(tool_result, ensure_ascii=False, default=str)
                })

            tool_used = ", ".join(tool_names)
            tool_data = tool_results[0]["data"] if len(tool_results) == 1 else tool_results

            # Second LLM call — generate human-readable response
            try:
                final_response = await self.client.chat.completions.create(
                    model=GROQ_MODEL,
                    messages=messages,
                    max_tokens=512,
                    temperature=0.4,
                )
                answer = final_response.choices[0].message.content
            except Exception as e:
                logger.error(f"Groq final call error: {e}")
                answer = self._format_tool_results(tool_results)

            if self._looks_like_tool_markup(answer):
                logger.warning("LLM returned tool markup after tool execution; using deterministic formatter")
                answer = self._format_tool_results(tool_results)

        else:
            # No tool needed — direct answer
            answer = response_message.content or "I can help with schedule, assignments, deadlines, and attendance."

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

    async def _rule_based_response(self, message: str, student_id: str) -> Dict[str, Any]:
        """Deterministic fallback for MVP reliability when LLM is unavailable."""
        intent, args = self._detect_intent(message)
        if not intent:
            return {
                "response": (
                    "I can help with academic data:\n"
                    "• schedule for today, tomorrow, or the week\n"
                    "• next class\n"
                    "• assignments and deadlines\n"
                    "• attendance and risky courses\n\n"
                    "For example: \"What is my next class?\" or \"Any attendance risks?\""
                ),
                "tool_used": None,
                "data": None,
            }

        data = await self._execute_tool(intent, args, student_id)
        return {
            "response": self._format_tool_response(intent, data),
            "tool_used": intent,
            "data": data,
        }

    def _detect_intent(self, message: str):
        text = message.lower()
        if any(word in text for word in ("посещ", "attendance", "absence", "absent", "пропуск", "риск", "қатысу")):
            return "get_attendance", {}
        if any(word in text for word in ("след", "next class", "next lesson", "ближай", "келесі")):
            return "get_next_class", {}
        if any(word in text for word in ("завтра", "tomorrow", "ертең")):
            return "get_schedule_tomorrow", {}
        if any(word in text for word in ("сегодня", "today", "бүгін")):
            return "get_schedule_today", {}
        if any(word in text for word in ("недел", "week", "расписание", "schedule", "кесте")):
            return "get_full_schedule", {}
        if any(word in text for word in ("дедлайн", "deadline", "due", "сроч", "urgent")):
            return "get_deadlines", {"days": 14}
        if any(word in text for word in ("задан", "assignment", "homework", "дз", "тапсыр", "сдать", "сдавать", "сдач", "домаш")):
            days = 7 if any(w in text for w in ("week", "недел", "апта")) else 30
            return "get_assignments", {"days": days, "include_submitted": False}
        return None, {}

    def _looks_like_tool_markup(self, answer: str | None) -> bool:
        if not answer:
            return True
        text = answer.lower()
        markers = (
            "<function>",
            "</function>",
            "get_attendance_status(",
            "get_attendance(",
            "get_assignments(",
            "get_deadlines(",
            "get_schedule",
            "tool_call",
        )
        return any(marker in text for marker in markers)

    def _format_tool_results(self, tool_results: List[Dict[str, Any]]) -> str:
        if len(tool_results) == 1:
            return self._format_tool_response(tool_results[0]["tool"], tool_results[0]["data"])
        return "\n\n".join(
            self._format_tool_response(result["tool"], result["data"])
            for result in tool_results
        )

    def _format_tool_response(self, tool_name: str, data: Any) -> str:
        if not data:
            return "No data is loaded yet. Try pressing Refresh data."
        if isinstance(data, dict) and data.get("error"):
            return f"Could not get the data: {data['error']}"

        if tool_name in {"get_assignments", "get_deadlines"}:
            assignments = data.get("assignments", []) if isinstance(data, dict) else []
            if not assignments:
                return "There are no active assignments in the selected period."
            lines = ["Upcoming assignments:"]
            for item in assignments[:8]:
                status = "submitted" if item.get("submitted") else f"in {item.get('days_left', '?')} day(s)"
                lines.append(f"• {item.get('title', 'Assignment')} - {item.get('course_name', '')}, {status}")
            return "\n".join(lines)

        if tool_name == "get_next_class":
            if not data.get("course_name"):
                return data.get("message", "No upcoming classes found.")
            when = "today" if data.get("is_today") else "tomorrow" if data.get("is_tomorrow") else data.get("day", "")
            return (
                f"Next class {when}:\n"
                f"{data.get('course_name')} ({data.get('class_type', 'Class')})\n"
                f"{data.get('start_time')}-{data.get('end_time')}, room {data.get('room') or 'not specified'}\n"
                f"Teacher: {data.get('teacher') or 'not specified'}"
            )

        if tool_name in {"get_schedule_today", "get_schedule_tomorrow", "get_schedule_by_day"}:
            classes = data.get("classes", []) if isinstance(data, dict) else []
            if not classes:
                return f"No classes for {data.get('day', 'this day')}."
            lines = [f"Schedule for {data.get('day', 'the day')}:"]
            for cls in classes:
                lines.append(f"• {cls.get('start_time')}-{cls.get('end_time')} {cls.get('course_name')} · {cls.get('room', '')}")
            return "\n".join(lines)

        if tool_name == "get_full_schedule":
            schedule = data.get("schedule", {}) if isinstance(data, dict) else {}
            if not schedule:
                return "Schedule is not loaded yet."
            lines = ["Weekly schedule:"]
            for day, classes in schedule.items():
                if not classes:
                    continue
                lines.append(f"\n{day}:")
                for cls in classes[:5]:
                    lines.append(f"• {cls.get('start_time')}-{cls.get('end_time')} {cls.get('course_name')} · {cls.get('room', '')}")
            return "\n".join(lines)

        if tool_name == "get_attendance":
            courses = data.get("courses", []) if isinstance(data, dict) else []
            if not courses:
                return "No attendance data is loaded yet."
            overall = data.get("overall_percentage", 0)
            low = [c for c in courses if c.get("percentage", 100) < 75]
            lines = [f"Overall attendance: {overall:.1f}%"]
            if low:
                lines.append("Courses at risk:")
                for course in low[:6]:
                    lines.append(
                        f"• {course.get('course_name')} - {course.get('percentage', 0):.1f}% "
                        f"({course.get('attended', 0)}/{course.get('total', 0)})"
                    )
            else:
                lines.append("No courses are below the 75% threshold.")
            return "\n".join(lines)

        return "The data was loaded, but I cannot format this response type yet."
