# SDU AI Agent — Frontend (Telegram Mini App)

React + Vite приложение для Telegram Mini App.

## Быстрый старт

```bash
npm install
cp .env.example .env
npm run dev
```

Открой http://localhost:3000

## Подключение к backend

В `.env`:
```
VITE_API_URL=http://localhost:8000
```

## Сборка для продакшена

```bash
npm run build
# Файлы будут в папке dist/
```

Загрузи `dist/` на любой хостинг (Netlify, Vercel, GitHub Pages).
Потом укажи URL в `telegram_bot.py`:
```python
MINI_APP_URL = "https://твой-домен.com"
```

## Структура

```
src/
├── App.jsx              # Routing + AuthProvider
├── main.jsx             # Entry point, Telegram WebApp init
├── index.css            # Design system (CSS variables)
├── api/client.js        # Все запросы к backend
├── hooks/useAuth.jsx    # Стейт студента
├── components/
│   └── BottomNav.jsx    # Нижняя навигация
└── pages/
    ├── LoginPage.jsx    # Вход по student_id + пароль
    ├── ChatPage.jsx     # AI чат (главный экран)
    ├── SchedulePage.jsx # Расписание по дням
    ├── AssignmentsPage.jsx # Задания и дедлайны
    └── AttendancePage.jsx  # Посещаемость с графиками
```

## Тестовые данные

```
student_id: 220103001
password: password123
```
