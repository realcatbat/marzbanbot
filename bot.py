import os
import threading
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv
from telegram import Update, KeyboardButton, ReplyKeyboardMarkup, Bot
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from telegram.helpers import escape_markdown
from telegram.error import Forbidden
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, Column, String, Integer, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests
import asyncio
import logging
import uuid

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Константа для призыва подписаться на канал
CHANNEL_TEXT = "\n\nПодписывайтесь на наш канал: https://t.me/your_channel"

# Инструкция по установке Outline Client
INSTRUCTION_TEXT = (
    "1. Установите приложение **Outline Client** на ваше устройство:\n"
    "- [iOS](https://apps.apple.com/us/app/outline-app/id1356177741)\n"
    "- [macOS](https://apps.apple.com/us/app/outline-secure-internet-access/id1356178125?mt=12)\n"
    "- [Android](https://play.google.com/store/apps/details?id=org.outline.android.client)\n"
    "- [Windows/Linux](https://getoutline.org/ru/get-started/#step-3)\n\n"
    "2. Откройте приложение и нажмите \"Добавить ключ\" или \"Add Server\".\n"
    "3. Вставьте ключ, который вы получили.\n"
    "4. Сохраните настройки и подключайтесь!\n\n"
)

# Функция безопасной отправки сообщений
async def safe_reply_text(message, text, **kwargs):
    try:
        await message.reply_text(text, **kwargs)
    except Forbidden:
        logging.warning("Невозможно отправить сообщение, бот заблокирован пользователем %s", message.chat_id)
    except Exception as e:
        logging.exception("Ошибка при отправке сообщения: %s", e)

# Загрузка .env
load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")
BASE_URL = os.getenv("BASE_URL")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))
PAYMENT_PROVIDER_TOKEN = os.getenv("PAYMENT_PROVIDER_TOKEN")
ITEM_PRICE = int(os.getenv("ITEM_PRICE", 20000))
YOOKASSA_SHOP_ID = os.getenv("YOOKASSA_SHOP_ID")
YOOKASSA_SECRET_KEY = os.getenv("YOOKASSA_SECRET_KEY")
DEFAULT_PREFIX = os.getenv("DEFAULT_PREFIX", "%16%03%01%00%C2%A8%01%01")
TRIAL_PASSWORD = os.getenv("TRIAL_PASSWORD", "trialpassword")
PAID_PASSWORD = os.getenv("PAID_PASSWORD", "supersecurepassword")
YOOKASSA_API_URL = os.getenv("YOOKASSA_API_URL", "https://api.yookassa.ru/v3/payments")

# Захардкоженная ссылка с двойным подчёркиванием
BOT_LINK = "https://t.me/your_bot"
logging.info(f"DEBUG: BOT_LINK (double underscore) = {BOT_LINK}")

TEST_MODE = (":TEST:" in (YOOKASSA_SHOP_ID or "")) or (":TEST:" in (YOOKASSA_SECRET_KEY or ""))
if TEST_MODE:
    logging.info("⚠️ Работаем в тестовом режиме YooKassa. Используются тестовые реквизиты.")
else:
    logging.info("✅ Работаем в production режиме YooKassa. Используются реальные реквизиты.")

engine = create_engine("sqlite:///subscriptions.db")
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    phone_number = Column(String, unique=True)
    subscription_type = Column(String)
    key = Column(String)
    expiration = Column(DateTime)
    chat_id = Column(String)
    payment_token = Column(String, nullable=True)

    referral_id = Column(String, unique=True)
    referred_by = Column(String, nullable=True)
    referral_count = Column(Integer, default=0)

Base.metadata.create_all(engine)

ADMIN_TOKEN = None
TOKEN_EXPIRES_AT = None

def get_admin_token():
    """Получает новый токен админа Marzban."""
    global ADMIN_TOKEN, TOKEN_EXPIRES_AT
    url = f"{BASE_URL}/api/admin/token"
    data = {"grant_type": "password", "username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        resp = requests.post(url, data=data, headers=headers)
        resp.raise_for_status()
        j = resp.json()
        ADMIN_TOKEN = j["access_token"]
        expires_in = int(j.get("expires_in", 3600))
        TOKEN_EXPIRES_AT = datetime.utcnow() + timedelta(seconds=expires_in)
        logging.info("Получен свежий токен, срок действия до %s", TOKEN_EXPIRES_AT)
        return ADMIN_TOKEN
    except Exception as e:
        logging.exception("Ошибка получения токена администратора: %s", e)
        exit(1)

def get_valid_admin_token():
    """Если токен скоро истекает, получаем новый."""
    global ADMIN_TOKEN, TOKEN_EXPIRES_AT
    if ADMIN_TOKEN is None or TOKEN_EXPIRES_AT is None or datetime.utcnow() >= TOKEN_EXPIRES_AT - timedelta(minutes=5):
        return get_admin_token()
    return ADMIN_TOKEN

def normalize_phone_number(phone_number):
    """Удаляем +, оставляем цифры."""
    return phone_number.replace("+", "")

def add_prefix_to_key(original_key, prefix):
    """Добавляем ?outline=1&prefix=... к Shadowsocks-ссылке."""
    parsed = urlparse(original_key)
    qs = parse_qs(parsed.query)
    qs["outline"] = ["1"]
    qs["prefix"] = [prefix]
    new_query = urlencode(qs, doseq=True)
    new_parsed = parsed._replace(query=new_query)
    return urlunparse(new_parsed)

# -----------------------------
# Логика подписок
# -----------------------------
def get_subscription(username):
    token = get_valid_admin_token()
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{BASE_URL}/api/user/{username}"
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        data = r.json()
        data["links"][0] = add_prefix_to_key(data["links"][0], DEFAULT_PREFIX)
        return data
    elif r.status_code == 404:
        return None
    else:
        raise Exception(f"Ошибка {r.status_code}: {r.text}")

def update_subscription(username, new_expire: datetime) -> bool:
    token = get_valid_admin_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = f"{BASE_URL}/api/user/{username}"
    data = {"status": "active", "expire": int(new_expire.timestamp())}
    r = requests.put(url, json=data, headers=headers)
    if r.status_code == 200:
        logging.info("Срок действия обновлён для %s", username)
        return True
    else:
        logging.error("Ошибка обновления: %s", r.text)
        return False

def get_or_create_user(username, phone_number, subscription_type):
    """Создаёт/получает юзера в Marzban."""
    token = get_valid_admin_token()
    headers = {"Authorization": f"Bearer {token}"}
    url_get = f"{BASE_URL}/api/user/{username}"
    try:
        resp = requests.get(url_get, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            key = data["links"][0]
            expiration = datetime.fromtimestamp(data["expire"]) if data.get("expire") else None
            status_raw = data["status"]
            if status_raw in ["active", "on_hold"]:
                status = "Активен" if status_raw == "active" else "Автосписание отключено"
            else:
                status = "Не активен"
            key = add_prefix_to_key(key, DEFAULT_PREFIX)
            return key, expiration, status
        elif resp.status_code == 404:
            # Создаём
            url_create = f"{BASE_URL}/api/user"
            if subscription_type == "trial":
                expire_days = 3
                passw = TRIAL_PASSWORD
            else:
                expire_days = 31
                passw = PAID_PASSWORD
            note_text = f"User created via Telegram Bot, type: {subscription_type}"
            create_data = {
                "username": username,
                "status": "active",
                "expire": int((datetime.utcnow() + timedelta(days=expire_days)).timestamp()),
                "data_limit": 0,
                "data_limit_reset_strategy": "no_reset",
                "note": note_text,
                "proxies": {"shadowsocks": {"password": passw, "method": "chacha20-ietf-poly1305"}},
                "inbounds": {"shadowsocks": ["Shadowsocks TCP"]}
            }
            c_resp = requests.post(url_create, json=create_data, headers=headers)
            if c_resp.status_code == 200:
                d = c_resp.json()
                key = d["links"][0]
                expiration = datetime.fromtimestamp(d["expire"])
                status = "Активен"
                key = add_prefix_to_key(key, DEFAULT_PREFIX)
                return key, expiration, status
            else:
                raise Exception(f"Ошибка создания: {c_resp.status_code}: {c_resp.text}")
        else:
            raise Exception(f"Ошибка GET: {resp.status_code}: {resp.text}")
    except Exception as e:
        logging.exception("Ошибка get_or_create_user")
        raise

def cancel_subscription_api(username):
    """Установка on_hold."""
    sub = get_subscription(username)
    if not sub:
        return False, "Подписка не оформлена"
    expire = sub.get("expire")
    if not expire:
        return False, "Не удалось получить срок"
    remaining = int(expire) - int(datetime.utcnow().timestamp())
    if remaining <= 0:
        return False, "Подписка уже истекла"
    token = get_valid_admin_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = f"{BASE_URL}/api/user/{username}"
    data = {"status": "on_hold", "on_hold_expire_duration": remaining}
    r = requests.put(url, json=data, headers=headers)
    if r.status_code == 200:
        logging.info("Автосписание отключено %s", username)
        return True, None
    else:
        return False, r.text

flask_app = Flask(__name__)

@flask_app.route("/webhook", methods=["POST"])
def webhook():
    """Обработка уведомлений от YooKassa."""
    try:
        data = request.get_json(force=True)
        logging.info("Webhook received data: %s", data)
        event = data.get("event")
        if event == "payment.succeeded":
            metadata = data.get("object", {}).get("metadata", {})
            order_id = metadata.get("order_id")
            phone_number = metadata.get("phone_number")
            chat_id = metadata.get("chat_id")
            
            # Валидация входных данных
            if not all([order_id, phone_number, chat_id]):
                logging.error("Отсутствуют обязательные поля в webhook")
                return jsonify({"status": "error", "message": "Missing required fields"}), 400
                
            if not phone_number.replace("+", "").isdigit():
                logging.error(f"Некорректный номер телефона: {phone_number}")
                return jsonify({"status": "error", "message": "Invalid phone number"}), 400

            try:
                new_expire = datetime.utcnow() + timedelta(days=31)
                username = f"{phone_number}_pay"

                if not update_subscription(username, new_expire):
                    logging.info("Пользователь %s не найден при обновлении, создаём заново", username)
                    key, expiration, status = get_or_create_user(username, phone_number, "paid")
                else:
                    key, expiration, status = get_or_create_user(username, phone_number, "paid")

                bot = Bot(token=BOT_TOKEN)
                key = add_prefix_to_key(key, DEFAULT_PREFIX)
                # Экранируем и заменяем \_
                escaped_key = escape_markdown(key, version=1).replace("\\_", "_")

                message_text = (
                    f"Ваш платеж прошел успешно. Ключ стоит 200 рублей.\n"
                    f"Ваш ключ: `{escaped_key}`\n"
                    f"Срок действия продлен до: {new_expire.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                    f"{INSTRUCTION_TEXT}"
                    f"{CHANNEL_TEXT}"
                )

                asyncio.run(bot.send_message(
                    chat_id=int(chat_id),
                    text=message_text,
                    parse_mode="Markdown"
                ))
                logging.info("Отправлен обновленный ключ пользователю %s", chat_id)

                payment = data.get("object", {})
                payment_method_token = payment.get("payment_method", {}).get("id")
                db_session = Session()
                
                try:
                    # Используем with для автоматического закрытия сессии
                    with db_session.begin():
                        user = db_session.query(User).filter(User.phone_number == phone_number).first()
                        if user is None:
                            user = User(
                                phone_number=phone_number,
                                subscription_type="paid",
                                key=key,
                                expiration=new_expire,
                                chat_id=chat_id,
                                payment_token=payment_method_token
                            )
                            db_session.add(user)
                        else:
                            if payment_method_token:
                                user.payment_token = payment_method_token
                            user.key = key
                            user.expiration = new_expire

                    # Рефералы
                    if user is not None and user.referred_by:
                        referrer = db_session.query(User).filter(User.referral_id == user.referred_by).first()
                        if referrer:
                            with db_session.begin():
                                referrer.referral_count = (referrer.referral_count or 0) + 1
                                if referrer.referral_count >= 5:
                                    forever_expire = datetime.utcnow() + timedelta(days=3650)
                                    ref_username = None
                                    if referrer.phone_number:
                                        ref_username = f"{referrer.phone_number}_pay"
                                    if ref_username:
                                        updated_ok = update_subscription(ref_username, forever_expire)
                                        if updated_ok:
                                            referrer.expiration = forever_expire
                                            try:
                                                asyncio.run(bot.send_message(
                                                    chat_id=int(referrer.chat_id),
                                                    text=(
                                                        "Поздравляем!\n\n"
                                                        "Вы пригласили 5 оплачивающих подписку пользователей. "
                                                        "Мы дарим вам бесплатный и бессрочный ключ!\n\n"
                                                        "Спасибо, что пользуетесь нашим сервисом!"
                                                    )
                                                ))
                                            except Exception as e:
                                                logging.exception(
                                                    "Ошибка при уведомлении реферера: %s", e
                                                )
                finally:
                    db_session.close()
                    
            except Exception as e:
                logging.exception("Ошибка при обработке платежа: %s", e)
                return jsonify({"status": "error", "message": str(e)}), 500
                
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        logging.exception("Ошибка в webhook: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500

def create_yookassa_payment(amount_value: float, order_id: str, phone_number: str, chat_id: str) -> str:
    """Создание платежа в YooKassa."""
    url = YOOKASSA_API_URL
    payload = {
        "amount": {"value": f"{amount_value:.2f}", "currency": "RUB"},
        "confirmation": {"type": "redirect", "return_url": "https://rcpn.ru/return"},
        "capture": True,
        "description": "Подписка на ключ (1 месяц)",
        "save_payment_method": True,
        "metadata": {
            "order_id": order_id,
            "phone_number": phone_number,
            "chat_id": chat_id
        },
        "receipt": {
            "customer": {"phone": phone_number},
            "items": [
                {
                    "description": "Подписка на ключ (1 месяц)",
                    "quantity": "1.00",
                    "amount": {"value": f"{amount_value:.2f}", "currency": "RUB"},
                    "vat_code": 1
                }
            ]
        }
    }
    headers = {"Content-Type": "application/json", "Idempotence-Key": order_id}
    try:
        resp = requests.post(url, json=payload, headers=headers, auth=(YOOKASSA_SHOP_ID, YOOKASSA_SECRET_KEY))
        if 200 <= resp.status_code < 300:
            pay_data = resp.json()
            confirmation_url = pay_data["confirmation"]["confirmation_url"]
            logging.info("Платеж создан: %s", confirmation_url)
            return confirmation_url
        else:
            logging.error("Ошибка создания платежа: %s", resp.text)
            return None
    except Exception as e:
        logging.exception("Ошибка вызова YooKassa API: %s", e)
        return None

async def unlink_payment_method(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Отвязка метода оплаты."""
    phone_number = context.user_data.get("phone_number")
    if not phone_number:
        context.user_data["subscription_type"] = "unlink"
        kb = [
            [KeyboardButton("Поделиться контактом", request_contact=True)],
            [KeyboardButton("Назад в меню")]
        ]
        await safe_reply_text(
            update.message,
            "Пожалуйста, поделитесь вашим контактом для отвязки карты:",
            reply_markup=ReplyKeyboardMarkup(kb, resize_keyboard=True)
        )
        return
    try:
        db_session = Session()
        user = db_session.query(User).filter(User.phone_number == phone_number).first()
        if user and user.payment_token:
            user.payment_token = None
            db_session.commit()
            await safe_reply_text(update.message, "Способ оплаты успешно отвязан.")
        else:
            await safe_reply_text(update.message, "У вас не привязан способ оплаты.")
    except Exception as e:
        await safe_reply_text(update.message, f"Ошибка при отвязке карты: {e}")

async def referral_program(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Показывает условия реферальной программы + просит контакт.
    """
    text_message = (
        "Реферальная программа\n\n"
        "Пригласите 5 человек, которые оплатят подписку, и получите ключ бесплатно и навсегда.\n\n"
        "Условия:\n"
        "1. Вы делитесь своей уникальной реферальной ссылкой.\n"
        "2. Ваши друзья переходят по ссылке и оплачивают подписку.\n"
        "3. После 5 успешно оплативших подписок вы получаете пожизненный доступ!\n"
        "Для получения ключа перейдите в пункт Статус подписки. Если вы выполнили все условия, то там появится информация о ключе.\n\n"
        "Чтобы получить свою реферальную ссылку, поделитесь вашим контактом."
    )
    kb = [
        [KeyboardButton("Поделиться контактом", request_contact=True)],
        [KeyboardButton("Назад в меню")]
    ]
    context.user_data["subscription_type"] = "referral"
    await safe_reply_text(
        update.message,
        text_message,
        reply_markup=ReplyKeyboardMarkup(kb, resize_keyboard=True)
    )

async def handle_referral_contact(update: Update, context: ContextTypes.DEFAULT_TYPE, phone_number: str):
    """Обработка контакта в реферальной программе."""
    chat_id = str(update.effective_user.id)
    db_session = Session()
    
    try:
        user = db_session.query(User).filter(User.phone_number == phone_number).first()
        if user is None:
            user = db_session.query(User).filter(User.chat_id == chat_id).first()

        if user is None:
            user = User(phone_number=phone_number, chat_id=chat_id, referral_count=0)
            db_session.add(user)
            db_session.commit()

        if not user.referral_id:
            try:
                user.referral_id = str(uuid.uuid4())
                db_session.commit()
            except Exception as e:
                logging.error(f"Ошибка при генерации referral_id: {e}")
                await safe_reply_text(update.message, "Произошла ошибка при создании реферальной ссылки. Попробуйте позже.")
                return

        # Двойное подчёркивание
        referral_link = f"{BOT_LINK}?start=ref_{user.referral_id}"
        logging.info(f"DEBUG referral_link = {referral_link}")

        already_referred = user.referral_count or 0
        left_to_invite = max(0, 5 - already_referred)

        # Без Markdown, чтобы __ не ломалось
        text_msg = (
            "Ваша реферальная ссылка\n\n"
            f"Пригласите ещё {left_to_invite} человек(а), которые оплатят подписку, "
            "чтобы получить ключ бесплатно и навсегда!\n\n"
            f"Ваша ссылка:\n{referral_link}\n\n"
            "Поделитесь ей с друзьями!\n\n"
            "Для получения ключа перейдите в пункт Статус подписки. Если вы выполнили все условия, то там появится информация о ключе."
        )
        await safe_reply_text(update.message, text_msg)
        logging.info(f"Отправляем пользователю текст:\n{text_msg}")
    except Exception as e:
        logging.exception("Ошибка в handle_referral_contact: %s", e)
        await safe_reply_text(update.message, "Произошла ошибка. Попробуйте позже.")
    finally:
        db_session.close()

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработка /start."""
    bot_info = await context.bot.get_me()
    logging.info(f"DEBUG: current bot username is: {bot_info.username}")

    ref_id = None
    if update.message and update.message.text:
        parts = update.message.text.split()
        if len(parts) > 1 and parts[1].startswith("ref_"):
            ref_id = parts[1].replace("ref_", "")

    if ref_id:
        chat_id = str(update.effective_user.id)
        db_sess = Session()
        user = db_sess.query(User).filter(User.chat_id == chat_id).first()
        if not user:
            user = User(chat_id=chat_id)
            db_sess.add(user)
        if not user.referred_by:
            user.referred_by = ref_id
        db_sess.commit()
        db_sess.close()

    description = (
        "✨ **Добро пожаловать в наш сервис!** ✨\n\n"
        "🔑 **Что мы предоставляем?**\n"
        "Вы получаете персональный ключ для настройки безопасного доступа к выбранным услугам. "
        "Ключ уникален и подходит для использования на большинстве устройств.\n\n"
        "💡 **Что входит в подписку?**\n"
        "- Персональный ключ для доступа.\n"
        "- Инструкции по настройке и использованию.\n"
        "- Техническая поддержка на всем протяжении подписки.\n\n"
        "🛠 **Как это работает?**\n"
        "1. После оплаты или получения пробного ключа вы получите инструкцию.\n"
        "2. Установите ключ на вашем устройстве, следуя шагам из инструкции.\n"
        "3. Наслаждайтесь доступом к выбранным услугам!\n\n"
        "📞 **Техническая поддержка**\n"
        "Если у вас возникнут вопросы, наша команда готова помочь вам в любое время.\n"
        "Просто выберите нужную опцию в меню."
        f"{CHANNEL_TEXT}"
    )
    kb = [
        [KeyboardButton("Подписка на 1 месяц (200 рублей)")],
        [KeyboardButton("Получить пробный ключ на 3 дня")],
        [KeyboardButton("Статус подписки")],
        [KeyboardButton("Реферальная программа")],
        [KeyboardButton("Отвязать карту")],
        [KeyboardButton("Техническая поддержка")],
        [KeyboardButton("О нас")]
    ]
    await safe_reply_text(
        update.message,
        description,
        parse_mode="Markdown",
        reply_markup=ReplyKeyboardMarkup(kb, resize_keyboard=True)
    )

async def about(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text_abt = (
        "**О нас**\n\n"
        "Мы предлагаем уникальную услугу, позволяющую получить индивидуальный ключ доступа..."
        # (остальной ваш текст без изменений)
        "\n\n"
        "Мы собираем и обрабатываем персональные данные..."
    )
    await safe_reply_text(update.message, text_abt, parse_mode="Markdown")

async def subscription_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    phone_number = context.user_data.get("phone_number")
    if not phone_number:
        context.user_data["subscription_type"] = "status"
        kb = [
            [KeyboardButton("Поделиться контактом", request_contact=True)],
            [KeyboardButton("Назад в меню")]
        ]
        await safe_reply_text(
            update.message,
            "Пожалуйста, поделитесь вашим контактом для проверки статуса подписки:",
            reply_markup=ReplyKeyboardMarkup(kb, resize_keyboard=True)
        )
        return

    username = f"{phone_number}_pay"
    sub_data = get_subscription(username)
    if sub_data is None:
        await safe_reply_text(update.message, "У вас не оформлена подписка.")
        return

    try:
        key = sub_data["links"][0]
        key = add_prefix_to_key(key, DEFAULT_PREFIX)
        expiration_ts = sub_data.get("expire")
        expiration_str = datetime.fromtimestamp(expiration_ts).strftime("%Y-%m-%d %H:%M:%S") if expiration_ts else "Неизвестно"
        status_raw = sub_data.get("status", "Не активен")
        if status_raw == "active":
            status = "Активен"
        elif status_raw == "on_hold":
            status = "Автосписание отключено"
        else:
            status = "Не активен"

        db_sess = Session()
        user_rec = db_sess.query(User).filter(User.phone_number == phone_number).first()
        card_status = "Привязана" if (user_rec and user_rec.payment_token) else "Не привязана"
        db_sess.close()

        # Сначала экранируем key (заменяем \_ -> _), а потом вставляем
        esc_key = escape_markdown(key, version=1).replace("\\_", "_")

        msg_text = (
            "📖 **Статус подписки**\n\n"
            f"🔑 Ваш ключ: `{esc_key}`\n"
            f"📅 Срок действия: {expiration_str}\n"
            f"⚡ Статус: {status}\n"
            "💰 Цена: 200 руб.\n"
            f"💳 Карта: {card_status}\n\n"
            f"{INSTRUCTION_TEXT}"
        )
        await safe_reply_text(update.message, msg_text, parse_mode="Markdown")
    except Exception as e:
        await safe_reply_text(update.message, f"Ошибка при получении статуса подписки: {e}")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    logging.info("Получено сообщение: %s", text)
    if text == "Подписка на 1 месяц (200 рублей)":
        context.user_data["subscription_type"] = "paid"
        await start_payment(update, context)
    elif text == "Получить пробный ключ на 3 дня":
        context.user_data["subscription_type"] = "trial"
        await request_contact(update, context, "trial")
    elif text == "Статус подписки":
        await subscription_status(update, context)
    elif text == "Реферальная программа":
        await referral_program(update, context)
    elif text == "Отвязать карту":
        await unlink_payment_method(update, context)
    elif text == "Техническая поддержка":
        await safe_reply_text(update.message, "Просьба написать в чат с @takeme2.")
    elif text == "О нас":
        await about(update, context)
    elif text == "Назад в меню":
        await start(update, context)
    else:
        await safe_reply_text(update.message, "Пожалуйста, выберите одну из доступных опций.")

async def start_payment(update: Update, context: ContextTypes.DEFAULT_TYPE):
    phone_number = context.user_data.get("phone_number")
    if not phone_number:
        context.user_data["subscription_type"] = "paid"
        kb = [
            [KeyboardButton("Поделиться контактом", request_contact=True)],
            [KeyboardButton("Назад в меню")]
        ]
        await safe_reply_text(
            update.message,
            "Пожалуйста, поделитесь вашим контактом перед оформлением подписки:",
            reply_markup=ReplyKeyboardMarkup(kb, resize_keyboard=True)
        )
        return

    order_id = f"monthly_subscription_{update.message.chat_id}_{int(datetime.utcnow().timestamp())}"
    amount_value = ITEM_PRICE / 100.0
    username = f"{phone_number}_pay"

    try:
        r = requests.get(
            f"{BASE_URL}/api/user/{username}",
            headers={"Authorization": f"Bearer {get_valid_admin_token()}"}
        )
        if r.status_code == 200:
            j = r.json()
            key = j["links"][0]
            expiration_ts = j.get("expire")
            expiration = datetime.fromtimestamp(expiration_ts) if expiration_ts else None
            status_raw = j["status"]
            if status_raw in ["active", "on_hold"]:
                status_msg = "Активен" if status_raw == "active" else "Автосписание отключено"
                key = add_prefix_to_key(key, DEFAULT_PREFIX)
                esc_key = escape_markdown(key, version=1)
                exp_str = expiration.strftime("%Y-%m-%d %H:%M:%S") if expiration else "Неизвестно"
                instr = (
                    "📖 **Ваш ключ действителен**\n\n"
                    f"🔑 Ваш ключ: `{esc_key}`\n"
                    f"📅 Срок действия: {exp_str}\n"
                    f"⚡ Статус: {status_msg}\n"
                    "💰 Цена: 200 руб.\n\n"
                    f"{INSTRUCTION_TEXT}{CHANNEL_TEXT}"
                )
                await safe_reply_text(update.message, instr, parse_mode="Markdown")
                return
            else:
                await safe_reply_text(update.message, "Ваш ключ существует, но он не активен. Продлеваем подписку...")
                return
        elif r.status_code != 404:
            await safe_reply_text(update.message, f"Ошибка получения данных пользователя: {r.text}")
            return
    except Exception as e:
        await safe_reply_text(update.message, f"Ошибка при проверке пользователя: {e}")

    logging.info("Создадим платеж через YooKassa: %s", order_id)
    confirmation_url = create_yookassa_payment(amount_value, order_id, phone_number, str(update.message.chat_id))
    if confirmation_url:
        await safe_reply_text(
            update.message,
            f"Пожалуйста, перейдите по ссылке для оплаты подписки (200 руб):\n{confirmation_url}"
        )
    else:
        await safe_reply_text(update.message, "Ошибка при создании платежа. Попробуйте позже.")

async def start_trial_key(update: Update, context: ContextTypes.DEFAULT_TYPE):
    phone_number = context.user_data.get("phone_number")
    if not phone_number:
        context.user_data["subscription_type"] = "trial"
        kb = [
            [KeyboardButton("Поделиться контактом", request_contact=True)],
            [KeyboardButton("Назад в меню")]
        ]
        await safe_reply_text(
            update.message,
            "Пожалуйста, поделитесь вашим контактом для получения пробного ключа:",
            reply_markup=ReplyKeyboardMarkup(kb, resize_keyboard=True)
        )
        return

    order_id = f"trial_subscription_{update.message.chat_id}_{int(datetime.utcnow().timestamp())}"
    trial_days = 3
    username = f"{phone_number}_trial"

    try:
        r = requests.get(
            f"{BASE_URL}/api/user/{username}",
            headers={"Authorization": f"Bearer {get_valid_admin_token()}"}
        )
        if r.status_code == 200:
            d = r.json()
            key = d["links"][0]
            expiration_ts = d.get("expire")
            expiration = datetime.fromtimestamp(expiration_ts) if expiration_ts else None
            status_raw = d["status"]
            if status_raw in ["active", "on_hold"]:
                status_msg = "Активен" if status_raw == "active" else "Автосписание отключено"
                key = add_prefix_to_key(key, DEFAULT_PREFIX)
                masked_key = escape_markdown(key, version=1).replace("\\_", "_")
                parsed = urlparse(masked_key)
                if parsed.fragment.startswith("rcPN-") and parsed.fragment.endswith("_trial"):
                    masked_fragment = f"rcPN-{phone_number}_trial"
                    masked_key = urlunparse(parsed._replace(fragment=masked_fragment))
                exp_str = expiration.strftime("%Y-%m-%d %H:%M:%S") if expiration else "Неизвестно"
                instr = (
                    "📖 **Ваш пробный ключ**\n\n"
                    f"🔑 Ваш пробный ключ: `{masked_key}`\n"
                    f"📅 Действителен до: {exp_str}\n"
                    f"⚡ Статус: {status_msg}\n\n"
                    f"{INSTRUCTION_TEXT}{CHANNEL_TEXT}"
                )
                await safe_reply_text(update.message, instr, parse_mode="Markdown")
                return
        elif r.status_code != 404:
            await safe_reply_text(update.message, f"Ошибка получения пробного пользователя: {r.text}")
            return
    except Exception as e:
        await safe_reply_text(update.message, f"Ошибка при проверке пробного пользователя: {e}")
        return

    logging.info("Создадим пробный ключ: %s", order_id)
    try:
        key, expiration, status = get_or_create_user(username, phone_number, "trial")
        key = add_prefix_to_key(key, DEFAULT_PREFIX)
        masked_key = escape_markdown(key, version=1).replace("\\_", "_")
        parsed = urlparse(masked_key)
        if parsed.fragment.startswith("rcPN-") and parsed.fragment.endswith("_trial"):
            masked_fragment = f"rcPN-{phone_number}_trial"
            masked_key = urlunparse(parsed._replace(fragment=masked_fragment))
        exp_str = expiration.strftime("%Y-%m-%d %H:%M:%S") if expiration else "Неизвестно"
        msg_text = (
            "📖 **Ваш пробный ключ**\n\n"
            f"🔑 Ваш пробный ключ: `{masked_key}`\n"
            f"📅 Действителен до: {exp_str}\n"
            f"⚡ Статус: {status}\n\n"
            f"{INSTRUCTION_TEXT}{CHANNEL_TEXT}"
        )
        await safe_reply_text(update.message, msg_text, parse_mode="Markdown")
    except Exception as e:
        await safe_reply_text(update.message, f"Ошибка при выдаче пробного ключа: {e}")

async def request_contact(update: Update, context: ContextTypes.DEFAULT_TYPE, subscription_type):
    kb = [
        [KeyboardButton("Поделиться контактом", request_contact=True)],
        [KeyboardButton("Назад в меню")]
    ]
    reply_markup = ReplyKeyboardMarkup(kb, resize_keyboard=True)
    context.user_data["subscription_type"] = subscription_type
    await safe_reply_text(update.message, "Пожалуйста, поделитесь вашим контактом:", reply_markup=reply_markup)

async def contact_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    contact = update.message.contact
    phone_number = normalize_phone_number(contact.phone_number)
    context.user_data["phone_number"] = phone_number
    logging.info("Получен контакт: %s", phone_number)
    sub_type = context.user_data.get("subscription_type")

    if sub_type == "trial":
        await start_trial_key(update, context)
    elif sub_type == "status":
        await subscription_status(update, context)
    elif sub_type == "unlink":
        await unlink_payment_method(update, context)
    elif sub_type == "referral":
        await handle_referral_contact(update, context, phone_number)
    else:
        await start_payment(update, context)

def main():
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    bot = Bot(token=BOT_TOKEN)
    loop.run_until_complete(bot.delete_webhook())

    application = Application.builder().token(BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_handler(MessageHandler(filters.CONTACT, contact_handler))

    threading.Thread(target=lambda: flask_app.run(host="0.0.0.0", port=FLASK_PORT), daemon=True).start()
    application.run_polling()

if __name__ == "__main__":
    main()