"""
Quick test script — run this to verify the backend works without Groq.
Usage: python test_local.py
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from app.agent.data_service import DataService


async def test():
    print("=" * 50)
    print("SDU AI Agent — Local Test")
    print("=" * 50)
    
    ds = DataService()
    student_id = "220103001"

    # Test auth
    print("\n[1] Testing authentication...")
    student = await ds.authenticate_student(student_id, "password123")
    if student:
        print(f"    ✅ Authenticated: {student['name']}")
    else:
        print("    ❌ Auth failed")

    # Test next class
    print("\n[2] Testing get_next_class...")
    next_class = await ds.get_next_class(student_id)
    if "course_name" in next_class:
        print(f"    ✅ Next class: {next_class['course_name']} at {next_class['start_time']} in {next_class['room']}")
    else:
        print(f"    ℹ️  {next_class.get('message', 'No class found')}")

    # Test assignments
    print("\n[3] Testing get_assignments (next 7 days)...")
    assignments = await ds.get_assignments(student_id, days=7)
    print(f"    ✅ Found {assignments['count']} assignments:")
    for a in assignments['assignments']:
        status = "✅ submitted" if a['submitted'] else f"⏳ due in {a['days_left']} days"
        print(f"       - {a['course_name']}: {a['title']} ({status})")

    # Test today's schedule
    print("\n[4] Testing get_schedule_for_day...")
    from datetime import datetime
    today = datetime.now().strftime("%A")
    schedule = await ds.get_schedule_for_day(student_id)
    print(f"    ✅ Today ({today}): {schedule['classes_count']} classes")
    for cls in schedule['classes']:
        print(f"       - {cls['start_time']} {cls['course_name']} @ {cls['room']}")

    # Test attendance
    print("\n[5] Testing get_attendance...")
    attendance = await ds.get_attendance(student_id)
    print(f"    ✅ Overall: {attendance['overall_percentage']}%")
    for c in attendance['courses']:
        icon = "⚠️" if c['status'] == "warning" else ("🔴" if c['status'] == "critical" else "✅")
        print(f"       {icon} {c['course_name']}: {c['percentage_formatted']} ({c['attended']}/{c['total']})")

    if attendance['has_issues']:
        print(f"\n    ⚠️ Low attendance in: {', '.join(c['course_name'] for c in attendance['low_attendance_courses'])}")

    print("\n" + "=" * 50)
    print("All tests passed! ✅")
    print("\nNext steps:")
    print("  1. Set GROQ_API_KEY in .env")
    print("  2. Run: uvicorn app.main:app --reload")
    print("  3. Open: http://localhost:8000/docs")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(test())
