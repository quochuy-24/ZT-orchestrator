"""Telegram Service - Send OTP via Telegram Bot"""

import httpx
import os

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "TELEGRAM_BOT_TOKEN")
TELEGRAM_API_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"


async def send_otp_telegram(chat_id: str, username: str, resource_name: str, otp_code: str):
    """Send OTP code to user via Telegram"""

    message = f"""
🔐 **JIT Access Request**

User: {username}
Resource: {resource_name}
OTP Code: `{otp_code}`

⏱ Valid for 5 minutes
    """.strip()

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{TELEGRAM_API_URL}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": message,
                    "parse_mode": "Markdown"
                }
            )
            response.raise_for_status()
            return True
    except Exception as e:
        print(f"Failed to send Telegram message: {e}")
        return False
