"""
SDU AI Agent — Telegram Bot
Handles bot commands and launches the Mini App.

Setup:
1. Create bot via @BotFather
2. Set TELEGRAM_BOT_TOKEN in .env
3. Run: python telegram_bot.py
"""

import asyncio
import logging
import os
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
MINI_APP_URL = os.getenv("MINI_APP_URL", "https://your-domain.com")


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command."""
    user = update.effective_user
    keyboard = [
        [InlineKeyboardButton(
            "📚 Open SDU Assistant",
            web_app=WebAppInfo(url=MINI_APP_URL)
        )]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        f"Привет, {user.first_name}! 👋\n\n"
        "Я SDU AI Assistant — твой академический помощник.\n\n"
        "Я могу помочь:\n"
        "📅 Расписание занятий\n"
        "📝 Задания и дедлайны\n"
        "✅ Статистика посещаемости\n\n"
        "Нажми кнопку, чтобы открыть ассистент:",
        reply_markup=reply_markup
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /help command."""
    await update.message.reply_text(
        "🎓 *SDU AI Assistant*\n\n"
        "Команды:\n"
        "/start — Открыть ассистент\n"
        "/help — Справка\n\n"
        "Через Mini App ты можешь спросить:\n"
        "• Какие у меня задания на этой неделе?\n"
        "• Какая следующая пара?\n"
        "• Какое расписание сегодня?\n"
        "• Какая у меня посещаемость?",
        parse_mode="Markdown"
    )


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle text messages (redirect to Mini App)."""
    keyboard = [
        [InlineKeyboardButton(
            "📚 Open SDU Assistant",
            web_app=WebAppInfo(url=MINI_APP_URL)
        )]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        "Открой Mini App для общения с AI ассистентом 👇",
        reply_markup=reply_markup
    )


def main():
    if not BOT_TOKEN:
        logger.error("TELEGRAM_BOT_TOKEN not set!")
        return

    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    logger.info("Bot started. Press Ctrl+C to stop.")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
