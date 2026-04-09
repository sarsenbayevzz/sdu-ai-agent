# SDU AI Agent — MVP Backend

AI-powered academic assistant for SDU students. Uses Groq LLM with tool-calling to answer questions about schedule, assignments, and attendance.

## Architecture

```
Telegram Mini App (React)
        ↓
  FastAPI Backend
        ↓
  ┌─────────────────────────┐
  │  SDU AI Agent (Groq)    │
  │  Tool-calling pipeline  │
  └─────────────────────────┘
        ↓
  ┌─────────────────────────┐
  │  Data Layer             │
  │  ├── Moodle API         │
  │  ├── SDU Portal         │
  │  └── Mock Data (dev)    │
  └─────────────────────────┘
        ↓
    SQLite / PostgreSQL
```

## Quick Start

### 1. Clone and configure

```bash
cd backend
cp .env.example .env
# Edit .env and set your GROQ_API_KEY
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the server

```bash
uvicorn app.main:app --reload
```

### 4. Open API docs

```
http://localhost:8000/docs
```

---

## Getting API Keys

### Groq API Key (FREE)
1. Go to https://console.groq.com
2. Sign up → API Keys → Create key
3. Add to `.env`: `GROQ_API_KEY=your_key`

### Telegram Bot Token
1. Open Telegram → search `@BotFather`
2. Send `/newbot` → follow instructions
3. Add to `.env`: `TELEGRAM_BOT_TOKEN=your_token`

---

## API Endpoints

| Method | URL | Description |
|--------|-----|-------------|
| POST | `/chat` | Main AI chat endpoint |
| POST | `/auth/login` | Student authentication |
| GET | `/assignments?student_id=X` | Get assignments |
| GET | `/schedule/today?student_id=X` | Today's schedule |
| GET | `/schedule/next?student_id=X` | Next class |
| GET | `/schedule/week?student_id=X` | Weekly schedule |
| GET | `/attendance?student_id=X` | Attendance stats |
| GET | `/health` | Health check |

### Chat Example

```bash
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Какие у меня задания на этой неделе?", "student_id": "220103001"}'
```

Response:
```json
{
  "response": "У тебя 3 задания на этой неделе:\n• Data Structures — Heap Implementation (через 5 дней)\n• Calculus II — Problem Set 4 (через 6 дней)\n• Physics — Lab Report #3 (через 7 дней)",
  "tool_used": "get_assignments",
  "data": {...}
}
```

---

## Moodle Integration

### How to get your Moodle token

```bash
curl -X POST https://moodle.sdu.edu.kz/login/token.php \
  -d "username=YOUR_STUDENT_ID&password=YOUR_PASS&service=moodle_mobile_app"
```

If this returns a token, Moodle API is available. Add to `.env`:
```
MOODLE_URL=https://moodle.sdu.edu.kz
USE_MOCK_DATA=false
```

### If Moodle API is not available

The app falls back to mock data automatically.  
To add real data: edit `app/integrations/sdu_portal.py` and implement the scraper.

---

## SDU Portal Integration

The `app/integrations/sdu_portal.py` contains a scraper skeleton.  
To implement:

1. Open `https://my.sdu.edu.kz` in browser devtools
2. Inspect the login form (find field names, CSRF token)
3. Update `SDUPortalClient.login()` with correct field names
4. Inspect schedule/attendance pages and implement parsers

---

## Project Structure

```
backend/
├── app/
│   ├── main.py              # FastAPI app entry point
│   ├── api/
│   │   ├── auth.py          # Authentication endpoints
│   │   ├── chat.py          # Chat endpoint
│   │   ├── assignments.py   # Assignments endpoints
│   │   ├── schedule.py      # Schedule endpoints
│   │   └── attendance.py    # Attendance endpoints
│   ├── agent/
│   │   ├── agent.py         # Groq AI agent with tool-calling
│   │   └── data_service.py  # Data retrieval service
│   ├── integrations/
│   │   ├── moodle.py        # Moodle API client
│   │   └── sdu_portal.py    # SDU portal scraper + mock data
│   ├── models/
│   │   └── database.py      # SQLAlchemy models + DB setup
│   └── schemas/
│       └── schemas.py       # Pydantic schemas
├── telegram_bot.py          # Telegram bot (Mini App launcher)
├── test_local.py            # Local test script
├── requirements.txt
├── Dockerfile
└── .env.example
```

---

## Development Roadmap

### ✅ Done (this MVP)
- FastAPI backend with all endpoints
- Groq AI agent with 6 tools
- Mock data for SDU (schedule, assignments, attendance)
- Moodle API client (ready for real token)
- SDU portal scraper skeleton
- JWT authentication
- Telegram bot skeleton
- Docker support

### 🔜 Next Steps
1. **Get Moodle token** → test real Moodle integration
2. **Implement SDU portal scraper** → get real schedule & attendance
3. **Build React Mini App** → chat UI + schedule page
4. **Deploy to Railway/Render** → public URL
5. **Connect Telegram bot** → set webhook

### 🔮 Future Features
- Real student authentication via SDU SSO
- PostgreSQL for production
- Chat history persistence
- Attendance alerts
- Deadline reminders via bot
- Socratic tutoring mode

---

## Test Credentials (Mock Data)

```
student_id: 220103001
password: password123
```

---

## Docker

```bash
cp backend/.env.example backend/.env
# Edit .env
docker-compose -f docker/docker-compose.yml up --build
```
