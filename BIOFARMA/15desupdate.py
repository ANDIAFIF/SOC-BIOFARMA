import json
import random
import time
import threading
import asyncio
import glob
import os
import requests
from telethon.sync import TelegramClient
from telethon.errors import SessionPasswordNeededError, PhoneCodeInvalidError, PhoneCodeExpiredError
from telethon.tl.functions.contacts import ImportContactsRequest
from telethon.tl.types import InputPhoneContact
import vobject
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from telegram import Update, ReplyKeyboardMarkup, KeyboardButton, InlineKeyboardMarkup, InlineKeyboardButton
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, ConversationHandler, CallbackContext, CallbackQueryHandler
import logging
import warnings

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

session = requests.Session()
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)
adapter = HTTPAdapter(
    max_retries=retry_strategy,
    pool_connections=1000,
    pool_maxsize=2000
)
session.mount("http://", adapter)
session.mount("https://", adapter)



warnings.filterwarnings("ignore", category=UserWarning, module="telegram.ext.conversationhandler")

                        
# Logging configuration
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)
logging.getLogger('telegram').setLevel(logging.INFO)  # Changed to INFO to reduce spam
logging.getLogger('telegram.ext').setLevel(logging.INFO)

logger.info("🚀 Bot ULTIMATE VERSION v3.0 initializing...")                        
                        
# API Configuration
API_ID = '16528366'
API_HASH = 'ca9dc45f1a383b6b084e48cf2f1f784c'
BOT_TOKEN = '7975830669:AAG-A73dBIICePssPR7_Ojf_fZx43WQG8Jo'

# Create necessary folders
for folder in ["sessions", "vcfs", "data"]:
    if not os.path.exists(folder):
        os.makedirs(folder)


# User management files
ADMIN_USERS_FILE = 'data/admin_users.json'
STAFF_USERS_FILE = 'data/staff_users.json'
ALLOWED_USERS_FILE = 'data/allowed_users.json'

# Conversation states
MENU, ASK_NUM_ACCOUNTS, INPUT_PHONES, INPUT_VERIFICATION_CODE, VCF, SELECT_ACCOUNT_DELETE, ADMIN_MENU, ADD_USER, CONFIRM_CONTINUE, VCF_SELECT, CHANGE_NUMBER, VCF_REUPLOAD, DELETE_USER_MENU, DELETE_SINGLE_USER, CONFIRM_DELETE_ALL, WAIT_FOR_NOTIFICATION_MESSAGE, INPUT_NEW_NUMBER, INPUT_VERIFICATION_CODE_FOR_CHANGE = range(18)

# Multithreaded data structures
user_verification_requests = defaultdict(dict)
verification_lock = threading.RLock()
user_semaphores = defaultdict(lambda: threading.Semaphore(1))

MAX_CONSECUTIVE_NOT_FOUND = 30

# ========== GANTI NOMOR PROTECTION SETTINGS ==========
MAX_NUMBER_CHANGES = 5  # Maximum 5x ganti nomor per proses
MIN_CHANGE_INTERVAL = 120  # Minimum 2 menit antara ganti nomor

# ============================================================
# 🔥 INSTANT RESPONSE FEATURES
# ============================================================

from functools import wraps

class MessageRateLimiter:
    """
    Rate limiter untuk prevent Telegram API flood
    Per-user rate limiting (1 msg per 100ms)
    """
    def __init__(self):
        self.last_message_time = {}
        self.lock = threading.Lock()
        self.min_interval = 0.1  # 100ms minimum interval
    
    def wait_if_needed(self, chat_id):
        """Wait jika message terlalu cepat"""
        with self.lock:
            current_time = time.time()
            
            if chat_id in self.last_message_time:
                elapsed = current_time - self.last_message_time[chat_id]
                if elapsed < self.min_interval:
                    wait_time = self.min_interval - elapsed
                    time.sleep(wait_time)
            
            self.last_message_time[chat_id] = time.time()
    
    def send_message(self, bot, chat_id, text, **kwargs):
        """Send message dengan rate limiting"""
        self.wait_if_needed(chat_id)
        return bot.send_message(chat_id=chat_id, text=text, **kwargs)

# Global rate limiter instance
rate_limiter = MessageRateLimiter()

def run_in_background(func):
    """
    Decorator to run function in background thread
    Makes bot non-blocking!
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        thread = threading.Thread(
            target=func,
            args=args,
            kwargs=kwargs,
            daemon=True
        )
        thread.start()
        logger.info(f"🔄 Background thread started: {func.__name__}")
        return thread
    return wrapper


# ========== HELPER FUNCTIONS ==========

def save_sessions(sessions):
    with open('sessions/sessions.json', 'w') as f:
        json.dump(sessions, f, indent=4)

def load_sessions():
    try:
        with open('sessions/sessions.json', 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_allowed_users(users):
    with open(ALLOWED_USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def load_allowed_users():
    try:
        with open(ALLOWED_USERS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_admin_users(users):
    with open(ADMIN_USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)
        
def save_staff_users(users):
    with open(STAFF_USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def load_admin_users():
    try:
        with open(ADMIN_USERS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    
def load_staff_users():
    try:
        with open(STAFF_USERS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def initialize_admin():
    admins = load_admin_users()
    if not admins:
        default_admin_id = 6888493665
        admins.append(default_admin_id)
        save_admin_users(admins)
        print(f"Admin default dengan ID {default_admin_id} telah ditambahkan")

def is_user_allowed(user_id):
    return is_admin(user_id) or is_staff(user_id)

def is_admin(user_id):
    admin_users = load_admin_users()
    return user_id in admin_users

def is_staff(user_id):
    staff_users = load_staff_users()
    return user_id in staff_users

def ensure_event_loop():
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
        
def run_async(coroutine):
    """Helper untuk menjalankan fungsi async dari fungsi synchronous"""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coroutine)

def cleanup_user_verification(user_id):
    """Cleanup verification untuk user tertentu"""
    try:
        with verification_lock:
            if user_id in user_verification_requests:
                user_requests = user_verification_requests[user_id]
                phones_to_cleanup = list(user_requests.keys())
                
                for phone in phones_to_cleanup:
                    try:
                        request_data = user_requests[phone]
                        if 'client' in request_data:
                            client = request_data['client']
                            if client and hasattr(client, 'is_connected'):
                                try:
                                    if client.is_connected():
                                        client.disconnect()
                                        logger.info(f"🔌 Disconnected client for user {user_id}, phone {phone}")
                                except Exception as disconnect_error:
                                    logger.error(f"❌ Disconnect error for user {user_id}: {disconnect_error}")
                    except Exception as e:
                        logger.error(f"❌ Error disconnecting client for user {user_id}, phone {phone}: {e}")
                
                del user_verification_requests[user_id]
                logger.info(f"🧹 Cleaned verification for user {user_id}")
    except Exception as e:
        logger.error(f"❌ Error in cleanup_user_verification for user {user_id}: {e}")          

def get_existing_sessions():
    """Get existing session files"""
    sessions_files = glob.glob("sessions/session_*")
    existing_sessions = []
    
    for session_file in sessions_files:
        session_name = os.path.basename(session_file).replace(".session", "")
        if session_name.endswith('-journal'):
            continue
        if session_name.startswith("session_"):
            phone_number = session_name.replace("session_", "")
            existing_sessions.append(phone_number)
    
    return existing_sessions

def paginate_list(items, page_size=10, current_page=1):
    """Membagi daftar menjadi halaman"""
    start_idx = (current_page - 1) * page_size
    end_idx = start_idx + page_size
    total_pages = (len(items) + page_size - 1) // page_size
    
    return items[start_idx:end_idx], total_pages


# ========== 🔥 PERBAIKAN UTAMA: AUTO-DETECT NOMOR ==========

def request_verification_code(phone_number, session_name, context, chat_id):
    """Request verification code dengan auto-save session info"""
    logger.info(f"Meminta kode verifikasi untuk {phone_number}")
    ensure_event_loop()
    
    user_id = context.user_data.get('user_id', chat_id)
    context.user_data['user_id'] = user_id
    
    try:
        # Cleanup old client
        with verification_lock:
            if user_id in user_verification_requests and phone_number in user_verification_requests[user_id]:
                logger.info(f"🧹 Cleaning old client for user {user_id}, phone {phone_number}")
                old_data = user_verification_requests[user_id][phone_number]
                try:
                    if 'client' in old_data and old_data['client'].is_connected():
                        old_data['client'].disconnect()
                except Exception as e:
                    logger.error(f"❌ Error disconnecting old client: {e}")
                del user_verification_requests[user_id][phone_number]
        
        # Remove old session files
        session_file = f"sessions/{session_name}.session"
        session_journal_file = f"sessions/{session_name}.session-journal"
        
        for file_path in [session_file, session_journal_file]:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    logger.info(f"🗑️ Removed old session file: {file_path}")
                except Exception as e:
                    logger.warning(f"⚠️ Cannot remove session file: {e}")
        
        # Create new client
        client = TelegramClient(
            f"sessions/{session_name}", 
            API_ID, 
            API_HASH,
            device_model="Desktop",
            system_version="Windows 10", 
            app_version="4.9.0",
            lang_code="en",
            system_lang_code="en"
        )
        
        client.connect()
        
        if not client.is_user_authorized():
            result = client.send_code_request(phone_number)
            
            context.bot.send_message(
                chat_id=chat_id, 
                text=f"✅ Kode verifikasi telah dikirim ke {phone_number}\n"
                     f"📱 Cek SMS atau aplikasi Telegram\n\n"
                     f"Silakan masukkan kode verifikasi:"
            )

            # 🔥 PENTING: Simpan info session untuk auto-detect nanti
            with verification_lock:
                if user_id not in user_verification_requests:
                    user_verification_requests[user_id] = {}
                
                user_verification_requests[user_id][phone_number] = {
                    'client': client,
                    'session_name': session_name,
                    'time_requested': time.time(),
                    'code_hash': result.phone_code_hash,
                    'user_id': user_id,
                    'chat_id': chat_id,
                    'phone_number': phone_number  # 🔥 TAMBAHAN: Save phone number
                }
            
            # 🔥 TAMBAHAN: Auto-save ke context untuk auto-detect
            context.user_data['last_login_phone'] = phone_number
            context.user_data['last_login_session'] = session_name
            
            return True
        else:
            context.bot.send_message(chat_id=chat_id, text=f"✅ Akun {phone_number} sudah login!")
            
            # 🔥 TAMBAHAN: Auto-save active session
            context.user_data['active_session'] = {
                'phone_number': phone_number,
                'session_name': session_name
            }
            
            client.disconnect()
            return True
            
    except Exception as e:
        logger.error(f"❌ Error in request_verification_code: {e}")
        context.bot.send_message(
            chat_id=chat_id, 
            text=f"❌ Terjadi kesalahan: {str(e)}"
        )
        return False

def verify_code(phone_number, code, context, chat_id):
    """Verify code dengan auto-save active session"""
    ensure_event_loop()
    
    user_id = context.user_data.get('user_id', chat_id)
    
    client = None
    session_name = None
    
    with verification_lock:
        if user_id not in user_verification_requests or phone_number not in user_verification_requests[user_id]:
            logger.warning(f"❌ No verification request found for user {user_id}, phone {phone_number}")
            
            keyboard = [
                [KeyboardButton("🔄 Login Ulang")],
                [KeyboardButton("📱 Ganti Nomor")],
                [KeyboardButton("⬅️ Kembali ke Menu Utama")]
            ]
            reply_markup = ReplyKeyboardMarkup(keyboard, one_time_keyboard=True)
            
            context.bot.send_message(
                chat_id=chat_id, 
                text=f"❌ Sesi verifikasi telah berakhir atau tidak valid.\n\nSilakan pilih opsi:",
                reply_markup=reply_markup
            )
            
            context.user_data['verification_expired'] = True
            context.user_data['last_phone'] = phone_number
            return False

        client = user_verification_requests[user_id][phone_number]['client']
        session_name = user_verification_requests[user_id][phone_number]['session_name']
    
    try:
        if not client.is_connected():
            client.connect()
        
        client.sign_in(phone=phone_number, code=code)

        if client.is_user_authorized():
            client.disconnect()

            # 🔥 PERBAIKAN UTAMA: Auto-save active session setelah login berhasil
            context.user_data['active_session'] = {
                'phone_number': phone_number,
                'session_name': session_name,
                'login_time': time.time()
            }
            
            logger.info(f"✅ Auto-saved active session for user {user_id}: {phone_number}")

            with verification_lock:
                if user_id in user_verification_requests and phone_number in user_verification_requests[user_id]:
                    del user_verification_requests[user_id][phone_number]
                    
                    if not user_verification_requests[user_id]:
                        del user_verification_requests[user_id]

            context.bot.send_message(
                chat_id=chat_id, 
                text=f"✅ Login berhasil untuk {phone_number}!\n\n"
                     f"🎯 Nomor ini sudah tersimpan otomatis.\n"
                     f"📤 Anda dapat langsung upload file VCF."
            )
            return True
        else:
            context.bot.send_message(
                chat_id=chat_id, 
                text=f"❌ Verifikasi gagal. Silakan coba lagi."
            )
            return False
            
    except PhoneCodeInvalidError:
        context.bot.send_message(
            chat_id=chat_id, 
            text=f"❌ Kode verifikasi tidak valid. Pastikan kode benar dan coba lagi."
        )
        return False
        
    except PhoneCodeExpiredError:
        try:
            if client and client.is_connected():
                client.disconnect()
        except:
            pass

        with verification_lock:
            if user_id in user_verification_requests and phone_number in user_verification_requests[user_id]:
                del user_verification_requests[user_id][phone_number]
                
                if not user_verification_requests[user_id]:
                    del user_verification_requests[user_id]

        keyboard = [
            [KeyboardButton("🔄 Login Ulang")],
            [KeyboardButton("📱 Ganti Nomor")],
            [KeyboardButton("⬅️ Kembali ke Menu Utama")]
        ]
        reply_markup = ReplyKeyboardMarkup(keyboard, one_time_keyboard=True)

        context.bot.send_message(
            chat_id=chat_id, 
            text=f"⏰ Kode verifikasi telah kedaluwarsa.\nSilakan pilih opsi:",
            reply_markup=reply_markup
        )
        
        context.user_data['otp_expired'] = True
        context.user_data['last_phone'] = phone_number
        return False
        
    except SessionPasswordNeededError:
        context.bot.send_message(
            chat_id=chat_id, 
            text="❌ Akun ini memerlukan verifikasi 2 langkah (2FA). Silakan login melalui aplikasi Telegram terlebih dahulu."
        )
        
        try:
            if client and client.is_connected():
                client.disconnect()
        except:
            pass

        with verification_lock:
            if user_id in user_verification_requests and phone_number in user_verification_requests[user_id]:
                del user_verification_requests[user_id][phone_number]
                
                if not user_verification_requests[user_id]:
                    del user_verification_requests[user_id]
        
        return False
        
    except Exception as e:
        context.bot.send_message(
            chat_id=chat_id, 
            text=f"❌ Terjadi kesalahan: {str(e)}"
        )
        logger.error(f"❌ Error in verify_code: {e}")
        
        try:
            if client and client.is_connected():
                client.disconnect()
        except:
            pass

        with verification_lock:
            if user_id in user_verification_requests and phone_number in user_verification_requests[user_id]:
                del user_verification_requests[user_id][phone_number]
                
                if not user_verification_requests[user_id]:
                    del user_verification_requests[user_id]
        
        return False


# ========== 🔥 PERBAIKAN: VCF UPLOAD HANDLER YANG AUTO-DETECT ==========

def handle_vcf_file(update: Update, context: CallbackContext) -> int:
    """
    🔥 ULTIMATE: Instant response handler with non-blocking processing
    """
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    
    logger.info(f"📁 VCF file received from user {user_id}")
    
    if not is_user_allowed(user_id):
        update.message.reply_text("❌ Anda tidak memiliki izin untuk menggunakan bot ini.")
        return ConversationHandler.END
    
    # ========== INSTANT RESPONSE 1 (< 100ms) ==========
    update.message.reply_text(
        "✅ FILE VCF DITERIMA!\n\n"
        "📥 Mengunduh file...\n"
        "⏳ Mohon tunggu sebentar..."
    )
    
    if update.message.document:
        document = update.message.document
        logger.info(f"📄 File: {document.file_name}")
        
        if not document.file_name.lower().endswith('.vcf'):
            update.message.reply_text("❌ File bukan VCF. Harus berakhiran .vcf")
            return VCF
        
        # Download file (fast - usually 1-5 seconds)
        file = document.get_file()
        file_path = f"vcfs/{user_id}_{document.file_name}"
        
        try:
            file.download(file_path)
            # ========== INSTANT RESPONSE 2 (< 5s) ==========
            context.bot.send_message(
                chat_id=chat_id,
                text="✅ File berhasil diunduh!\n"
                     "🚀 Memulai proses import kontak...\n\n"
                     "📱 Proses berjalan di background.\n"
                     "💬 Bot tetap bisa menerima command lain!\n\n"
                     "Anda akan menerima update progress."
            )
            logger.info(f"✅ File downloaded: {file_path}")
        except Exception as e:
            logger.error(f"❌ Download error: {e}")
            update.message.reply_text(f"❌ Gagal mengunduh: {e}")
            return VCF
        
        # 🔥 Get active session - auto-detect!
        active_session = context.user_data.get('active_session')
        
        if not active_session:
            existing_sessions = get_existing_sessions()
            
            if not existing_sessions:
                context.bot.send_message(
                    chat_id=chat_id,
                    text="❌ Tidak ada nomor yang login.\n"
                         "Silakan login dengan /start"
                )
                return start(update, context)
            
            if len(existing_sessions) == 1:
                # Auto-use single session
                phone_number = existing_sessions[0]
                session_name = f"session_{phone_number}"
                
                context.user_data['active_session'] = {
                    'phone_number': phone_number,
                    'session_name': session_name
                }
                
                context.bot.send_message(
                    chat_id=chat_id,
                    text=f"✅ Auto-detected: {phone_number}"
                )
            else:
                # Multiple sessions - ask user to choose
                context.bot.send_message(
                    chat_id=chat_id,
                    text="📱 Beberapa nomor tersedia. Pilih:"
                )
                
                keyboard = []
                for i, phone in enumerate(existing_sessions[:10], 1):
                    keyboard.append([KeyboardButton(f"{i}. {phone}")])
                keyboard.append([KeyboardButton("⬅️ Kembali")])
                
                reply_markup = ReplyKeyboardMarkup(keyboard, one_time_keyboard=True)
                update.message.reply_text("Pilih nomor:", reply_markup=reply_markup)
                
                context.user_data['existing_sessions'] = existing_sessions
                context.user_data['vcf_file'] = document
                context.user_data['waiting_for_number_choice'] = True
                
                return VCF_SELECT
        else:
            phone_number = active_session['phone_number']
            session_name = active_session['session_name']
            
            context.bot.send_message(
                chat_id=chat_id,
                text=f"✅ Menggunakan: {phone_number}"
            )
        
        # ========== START BACKGROUND PROCESSING (NON-BLOCKING!) ==========
        @run_in_background
        def process_vcf_wrapper():
            """Wrapper untuk process_vcf di background"""
            try:
                process_vcf(file_path, session_name, phone_number, context)
            except Exception as e:
                logger.error(f"❌ Process error: {e}")
                rate_limiter.send_message(
                    context.bot, chat_id,
                    f"❌ Error: {str(e)}\n\nSilakan coba lagi."
                )
        
        # Start processing
        process_vcf_wrapper()
        
        # ========== RETURN IMMEDIATELY! Bot is free! ==========
        return VCF_REUPLOAD
    
    else:
        update.message.reply_text("❌ Silakan kirim file VCF.")
        return VCF


def handle_vcf_selection(update: Update, context: CallbackContext) -> int:
    """Handler untuk pemilihan nomor sebelum proses VCF"""
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    
    text = update.message.text.strip()
    
    if text == "⬅️ Kembali":
        return start(update, context)
    
    # Extract number from selection
    try:
        # Format: "1. +6281234567890"
        number_index = int(text.split(".")[0]) - 1
        existing_sessions = context.user_data.get('existing_sessions', [])
        
        if 0 <= number_index < len(existing_sessions):
            phone_number = existing_sessions[number_index]
            session_name = f"session_{phone_number}"
            
            # Set as active session
            context.user_data['active_session'] = {
                'phone_number': phone_number,
                'session_name': session_name
            }
            
            update.message.reply_text(
                f"✅ Nomor terpilih: {phone_number}\n"
                f"📥 Mengunduh file VCF..."
            )
            
            # Get saved file
            document = context.user_data.get('vcf_file')
            if document:
                file = document.get_file()
                file_path = f"vcfs/{document.file_name}"
                
                try:
                    file.download(file_path)
                    update.message.reply_text("✅ File berhasil diunduh!")
                    
                    # Start processing
                    update.message.reply_text(
                        f"🔄 Memproses file VCF...\n"
                        f"Anda dapat menghentikan dengan /stop"
                    )
                    
                    threading.Thread(
                        target=process_vcf,
                        args=(file_path, session_name, phone_number, context),
                        daemon=True
                    ).start()
                    
                    return VCF_REUPLOAD
                    
                except Exception as e:
                    update.message.reply_text(f"❌ Error: {e}")
                    return VCF
            else:
                update.message.reply_text("❌ File tidak ditemukan. Silakan upload ulang.")
                return VCF
        else:
            update.message.reply_text("❌ Pilihan tidak valid. Silakan pilih nomor dari daftar.")
            return VCF_SELECT
            
    except:
        update.message.reply_text("❌ Format tidak valid. Silakan pilih nomor dari daftar.")
        return VCF_SELECT


# ========== VCF PROCESSING (dipertahankan dari code asli) ==========

def parse_vcf_file(filename):
    """Parse VCF file and extract contacts"""
    contacts = []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            vcard_data = f.read()
        
        for vcard in vobject.readComponents(vcard_data):
            if hasattr(vcard, 'fn'):
                name = vcard.fn.value
            else:
                name = "Unknown"
            
            if hasattr(vcard, 'tel'):
                if isinstance(vcard.tel_list, list):
                    for tel in vcard.tel_list:
                        phone = tel.value.strip().replace(" ", "").replace("-", "")
                        contacts.append((name, phone))
                else:
                    phone = vcard.tel.value.strip().replace(" ", "").replace("-", "")
                    contacts.append((name, phone))
        
        logger.info(f"✅ Parsed {len(contacts)} contacts from VCF")
        return contacts
    
    except Exception as e:
        logger.error(f"❌ Error parsing VCF: {e}")
        return []


def process_vcf(filename, session_name, phone_number, context):
    """
    Process VCF file - IMPROVED with better connection handling
    """
    chat_id = context.user_data.get('chat_id')
    if not chat_id:
        logger.error("❌ chat_id not found in user_data")
        return
    
    logger.info(f"🔄 Starting VCF processing for {phone_number}")

    # ========== SAFE SEND HELPER FUNCTION ==========
    def safe_send(text, **kwargs):
        """
        Send message dengan proper error handling dan retry
        """
        max_retries = 3
        for attempt in range(max_retries):
            try:
                logger.info(f"📤 Sending message (attempt {attempt + 1}): {text[:50]}...")

                result = context.bot.send_message(
                    chat_id=chat_id,
                    text=text,
                    **kwargs
                )

                logger.info(f"✅ Message sent successfully! (msg_id: {result.message_id})")
                return result

            except Exception as e:
                logger.error(f"❌ Send failed (attempt {attempt + 1}): {type(e).__name__}: {str(e)}")

                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 2
                    logger.info(f"⏳ Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
                else:
                    logger.error(f"❌ ALL ATTEMPTS FAILED for message: {text[:100]}")
                    return None
    # ========== END SAFE SEND ==========

    contacts = parse_vcf_file(filename)
    if not contacts:
        safe_send("❌ Tidak ada kontak ditemukan dalam file VCF.")
        return

    safe_send(f"📊 Total kontak: {len(contacts)}\n🔄 Memulai proses import...")
    
    # Create new event loop for this thread
    ensure_event_loop()
    
    watchdog_active = True
    
    try:
        # Create Telegram client
        client = TelegramClient(
            f"sessions/{session_name}", 
            API_ID, 
            API_HASH,
            connection_retries=15,
            retry_delay=2,
            auto_reconnect=True,
            request_retries=7,
            timeout=60,
            flood_sleep_threshold=60
        )

        try:
            client.connect()
            connected = False
            for attempt in range(30):
                if client.is_connected():
                    connected = True
                    logger.info(f"✅ Client connected for {phone_number} (attempt {attempt + 1})")
                    break
                time.sleep(1)
            if not connected:
                raise ConnectionError("Timeout connecting client")
        except Exception as e:
            safe_send(f"❌ Connection failed: {str(e)}")
            return

        if not client.is_user_authorized():
            safe_send("❌ Not logged in. Please login first.")
            return

        consecutive_not_found = 0
        should_stop = False
        last_activity_time = time.time()
        connection_lock = threading.RLock()
        
        # Connection watchdog
        def connection_watchdog():
            nonlocal last_activity_time, client, watchdog_active
            
            while watchdog_active and client:
                try:
                    with connection_lock:
                        current_time = time.time()
                        
                        if not client or not hasattr(client, 'is_connected'):
                            logger.warning(f"⚠️ Invalid client for {phone_number}, stopping watchdog")
                            break
                            
                        if client.is_connected():
                            if current_time - last_activity_time > 180:
                                logger.warning(f"⚠️ Connection inactive for 3 minutes, reconnecting")
                                try:
                                    client.disconnect()
                                    time.sleep(2)
                                    client.connect()
                                    last_activity_time = current_time
                                    logger.info(f"✅ Reconnected for {phone_number}")
                                except Exception as e:
                                    logger.error(f"❌ Reconnect error: {str(e)}")
                        else:
                            logger.warning(f"⚠️ Client disconnected, reconnecting")
                            try:
                                client.connect()
                                last_activity_time = current_time
                                logger.info(f"✅ Reconnected for {phone_number}")
                            except Exception as e:
                                logger.error(f"❌ Reconnect error: {str(e)}")
                
                except Exception as e:
                    logger.error(f"❌ Watchdog error: {str(e)}")
                
                for _ in range(30):
                    if not watchdog_active:
                        break
                    time.sleep(1)
        
        watchdog_thread = threading.Thread(target=connection_watchdog, daemon=True)
        watchdog_thread.start()
        logger.info(f"🐕 Watchdog started for {phone_number}")

        CHUNK_SIZE = 20
        total_chunks = (len(contacts) + CHUNK_SIZE - 1) // CHUNK_SIZE

        for chunk_idx in range(total_chunks):
            if should_stop:
                safe_send("✅ Process stopped.")
                break

            start_idx = chunk_idx * CHUNK_SIZE
            end_idx = min(start_idx + CHUNK_SIZE, len(contacts))
            chunk = contacts[start_idx:end_idx]

            safe_send(f"💼 Processing batch {chunk_idx+1}/{total_chunks} (contacts {start_idx+1}-{end_idx})")
            
            # Verify connection
            with connection_lock:
                if not client.is_connected():
                    try:
                        logger.info(f"🔄 Reconnecting client for {phone_number}")
                        client.connect()
                        if not client.is_connected():
                            raise ConnectionError("Failed to reconnect")
                        last_activity_time = time.time()
                    except Exception as e:
                        safe_send(f"❌ Connection failed: {str(e)}")
                        break

            for rel_idx, (name, phone) in enumerate(chunk):
                index = start_idx + rel_idx + 1
                
                with connection_lock:
                    last_activity_time = time.time()
                
                if should_stop:
                    break
                
                first_name = name.split()[0] if name else "Kontak"
                last_name = " ".join(name.split()[1:]) if len(name.split()) > 1 else str(index)
                client_id = random.randint(100000, 999999)

                contact = InputPhoneContact(
                    client_id=client_id,
                    phone=phone,
                    first_name=first_name,
                    last_name=last_name
                )

                try:
                    result = client(ImportContactsRequest([contact]))
                    user = result.users[0] if result.users else None

                    if user:
                        safe_send(f"✅ [{index}] {name} - {phone} Okeni.")
                        consecutive_not_found = 0
                    else:
                        safe_send(f"⚠️ [{index}] {name} - {phone} jelek")
                        consecutive_not_found += 1
                        logger.info(f"Consecutive not found: {consecutive_not_found}/{MAX_CONSECUTIVE_NOT_FOUND}")
                    
                    # Check if reached limit
                    if consecutive_not_found >= MAX_CONSECUTIVE_NOT_FOUND:
                        logger.info("Reached max consecutive not found, showing options")
                        
                        # Save process state
                        context.user_data['current_vcf_process'] = {
                            'filename': filename,
                            'session_name': session_name,
                            'phone_number': phone_number,
                            'next_index': index + 1,
                            'contacts': contacts
                        }

                        callback_timestamp = int(time.time() * 1000)
                        
                        keyboard = [
                            [InlineKeyboardButton("Ya", callback_data=f"continue_yes_{callback_timestamp}")],
                            [InlineKeyboardButton("Ganti Nomor", callback_data=f"change_number_{callback_timestamp}")],
                            [InlineKeyboardButton("Tidak", callback_data=f"continue_no_{callback_timestamp}")]
                        ]
                        reply_markup = InlineKeyboardMarkup(keyboard)

                        try:
                            time.sleep(1)
                            safe_send(
                                f"⚠️ {MAX_CONSECUTIVE_NOT_FOUND} kontak berturut-turut tidak ditemukan.\n\n"
                                f"📱 Nomor: {phone_number}\n"
                                f"📊 Kontak terproses: {index}\n\n"
                                f"Apakah ingin melanjutkan?",
                                reply_markup=reply_markup
                            )
                            logger.info(f"✅ Keyboard sent with timestamp {callback_timestamp}")
                        except Exception as e:
                            logger.error(f"❌ Error sending keyboard: {e}")
                        
                        # Cleanup
                        watchdog_active = False
                        try:
                            if client and client.is_connected():
                                client.disconnect()
                                logger.info(f"🔌 Client disconnected")
                        except Exception as e:
                            logger.error(f"❌ Error closing client: {str(e)}")
                        
                        return
                    
                    # Delay with jitter
                    base_delay = 5
                    jitter = random.uniform(0, 2)
                    time.sleep(base_delay + jitter)

                except Exception as e:
                    error_msg = str(e)
                    logger.error(f"❌ Error processing contact {name}: {error_msg}")
                    safe_send(f"❌ [{index}] Failed: {name}: {error_msg}")

                    # Handle flood control
                    if any(keyword in error_msg.lower() for keyword in ["flood", "wait", "too many", "rate limit"]):
                        wait_time = 30

                        import re
                        wait_match = re.search(r'(\d+)', error_msg)
                        if wait_match:
                            try:
                                extracted_time = int(wait_match.group(1))
                                wait_time = min(extracted_time, 300)
                            except:
                                pass

                        safe_send(f"⚠️ Rate limit detected. Waiting {wait_time} seconds...")

                        remaining = wait_time
                        while remaining > 0:
                            sleep_chunk = min(30, remaining)
                            time.sleep(sleep_chunk)
                            remaining -= sleep_chunk

                            if remaining > 0 and remaining % 60 == 0:
                                safe_send(f"⏳ Waiting {remaining} more seconds...")
            
            # Delay between chunks
            if chunk_idx < total_chunks - 1:
                time.sleep(5 + random.uniform(0, 2))

        # Stop watchdog
        watchdog_active = False
        if watchdog_thread and watchdog_thread.is_alive():
            logger.info(f"🐕 Stopping watchdog - process complete")

        # Send completion message
        completion_timestamp = int(time.time() * 1000)
        safe_send("✅ Process complete!")

        # Save active session
        context.user_data['active_session'] = {
            'phone_number': phone_number,
            'session_name': session_name,
            'completion_timestamp': completion_timestamp
        }

        # Offer reupload
        def send_reupload_message():
            time.sleep(2)
            try:
                safe_send(
                    "📤 Ready for new VCF upload!\n\n"
                    f"Active number: {phone_number}\n\n"
                    "Please send new VCF file (must be .vcf format)"
                )

                keyboard = [
                    [InlineKeyboardButton("📱 Change Number", callback_data=f"change_number_new_vcf_{completion_timestamp}")],
                    [InlineKeyboardButton("⬅️ Back to Menu", callback_data=f"back_to_menu_{completion_timestamp}")]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)

                safe_send("Or choose other option:", reply_markup=reply_markup)
                logger.info(f"✅ Reupload buttons sent")

            except Exception as e:
                logger.error(f"❌ Error sending reupload message: {str(e)}")

        threading.Thread(target=send_reupload_message, daemon=True).start()

    except FileNotFoundError:
        safe_send("❌ VCF file not found.")
        logger.error(f"❌ VCF file not found: {filename}")
    except Exception as e:
        safe_send(f"❌ Error processing file: {str(e)}")
        logger.error(f"❌ Error in process_vcf: {str(e)}")
    finally:
        watchdog_active = False
        
        try:
            if watchdog_thread and watchdog_thread.is_alive():
                logger.info("🐕 Stopping watchdog - cleanup")
        except:
            pass
        
        try:
            if client and client.is_connected():
                client.disconnect()
                logger.info(f"🔌 Client disconnected in finally block")
        except Exception as e:
            logger.error(f"❌ Error disconnecting client in finally: {str(e)}")


# ========== CONVERSATION HANDLERS (simplified dari code asli) ==========

def start(update: Update, context: CallbackContext) -> int:
    """Start command handler"""
    # Handle None update
    if update is None:
        user_id = context.user_data.get('user_id')
        chat_id = context.user_data.get('chat_id')
    else:
        user_id = update.effective_user.id
        chat_id = update.effective_chat.id
        context.user_data['user_id'] = user_id
        context.user_data['chat_id'] = chat_id
    
    logger.info(f"🚀 Start called by user {user_id}")
    
    if not is_user_allowed(user_id):
        message = "❌ You don't have permission to use this bot."
        if update:
            update.message.reply_text(message)
        else:
            context.bot.send_message(chat_id=chat_id, text=message)
        return ConversationHandler.END
    
    # Cleanup
    cleanup_user_verification(user_id)
    
    # Build menu
    if is_admin(user_id):
        keyboard = [
            [KeyboardButton("🔑 Login Akun Baru")],
            [KeyboardButton("📝 Cek Nomor yang Login")],
            [KeyboardButton("🗑️ Hapus Nomor yang Login")],
            [KeyboardButton("👑 Menu Admin")]
        ]
    else:
        keyboard = [
            [KeyboardButton("🔑 Login Akun Baru")],
            [KeyboardButton("📝 Cek Nomor yang Login")],
            [KeyboardButton("🗑️ Hapus Nomor yang Login")]
        ]
    
    reply_markup = ReplyKeyboardMarkup(keyboard, one_time_keyboard=True)
    message = "🤖 Welcome to IT BOLDAR Bot!\n\nSilakan pilih menu:"
    
    if update:
        update.message.reply_text(message, reply_markup=reply_markup)
    else:
        context.bot.send_message(chat_id=chat_id, text=message, reply_markup=reply_markup)
    
    return MENU


def handle_menu(update: Update, context: CallbackContext) -> int:
    """Handle main menu selection"""
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    text = update.message.text
    
    logger.info(f"📋 Menu handler: {text} from user {user_id}")
    
    context.user_data['user_id'] = user_id
    context.user_data['chat_id'] = chat_id
    
    if text == "🔑 Login Akun Baru":
        update.message.reply_text("📱 Berapa banyak akun yang ingin Anda login?")
        return ASK_NUM_ACCOUNTS
        
    elif text == "📝 Cek Nomor yang Login":
        existing_sessions = get_existing_sessions()
        if not existing_sessions:
            update.message.reply_text("❌ Tidak ada nomor yang login.")
            return start(update, context)
        
        message = "📱 Nomor yang sudah login:\n\n"
        for i, phone in enumerate(existing_sessions, 1):
            message += f"{i}. {phone}\n"
        
        # 🔥 TAMBAHAN: Show active session if exists
        active_session = context.user_data.get('active_session')
        if active_session:
            message += f"\n✅ Nomor aktif saat ini: {active_session['phone_number']}"
        
        update.message.reply_text(message)
        return start(update, context)
        
    elif text == "🗑️ Hapus Nomor yang Login":
        existing_sessions = get_existing_sessions()
        if not existing_sessions:
            update.message.reply_text("❌ Tidak ada nomor yang login.")
            return start(update, context)
        
        keyboard = []
        for i, phone in enumerate(existing_sessions[:10], 1):
            keyboard.append([KeyboardButton(f"{i}. {phone}")])
        keyboard.append([KeyboardButton("⬅️ Kembali")])
        
        reply_markup = ReplyKeyboardMarkup(keyboard, one_time_keyboard=True)
        update.message.reply_text("Pilih nomor yang akan dihapus:", reply_markup=reply_markup)
        
        context.user_data['existing_sessions'] = existing_sessions
        return SELECT_ACCOUNT_DELETE
        
    elif text == "👑 Menu Admin" and is_admin(user_id):
        keyboard = [
            [KeyboardButton("➕ Tambah Staff")],
            [KeyboardButton("🗑️ Hapus Staff")],
            [KeyboardButton("📊 Lihat Statistik")],
            [KeyboardButton("⬅️ Kembali")]
        ]
        reply_markup = ReplyKeyboardMarkup(keyboard, one_time_keyboard=True)
        update.message.reply_text("👑 Menu Admin:", reply_markup=reply_markup)
        return ADMIN_MENU
    
    else:
        update.message.reply_text("❌ Pilihan tidak valid.")
        return start(update, context)


def ask_num_accounts(update: Update, context: CallbackContext) -> int:
    """Ask how many accounts to login"""
    text = update.message.text.strip()
    
    try:
        num_accounts = int(text)
        if num_accounts < 1 or num_accounts > 10:
            update.message.reply_text("❌ Jumlah harus antara 1-10.")
            return ASK_NUM_ACCOUNTS
        
        context.user_data['num_accounts'] = num_accounts
        context.user_data['phones'] = []
        context.user_data['current_phone_index'] = 0
        
        update.message.reply_text(
            f"📱 Masukkan nomor telepon ke-1 (format: +62xxx):"
        )
        return INPUT_PHONES
        
    except ValueError:
        update.message.reply_text("❌ Masukkan angka yang valid.")
        return ASK_NUM_ACCOUNTS


def input_phones(update: Update, context: CallbackContext) -> int:
    """Input phone numbers"""
    phone = update.message.text.strip()
    
    if not phone.startswith('+'):
        update.message.reply_text("❌ Nomor harus diawali dengan + (contoh: +6281234567890)")
        return INPUT_PHONES
    
    context.user_data['phones'].append(phone)
    context.user_data['current_phone_index'] += 1
    
    if context.user_data['current_phone_index'] < context.user_data['num_accounts']:
        update.message.reply_text(
            f"📱 Masukkan nomor telepon ke-{context.user_data['current_phone_index'] + 1}:"
        )
        return INPUT_PHONES
    else:
        # All phones collected, start verification
        context.user_data['verification_index'] = 0
        
        phone_number = context.user_data['phones'][0]
        session_name = f"session_{phone_number}"
        
        request_verification_code(phone_number, session_name, context, update.effective_chat.id)
        
        return INPUT_VERIFICATION_CODE


def input_verification_code(update: Update, context: CallbackContext) -> int:
    """Input verification code"""
    code = update.message.text.strip()
    chat_id = update.effective_chat.id
    
    verification_index = context.user_data.get('verification_index', 0)
    phones = context.user_data.get('phones', [])
    
    if verification_index >= len(phones):
        update.message.reply_text("❌ Error: Invalid verification index.")
        return start(update, context)
    
    phone_number = phones[verification_index]
    
    # Verify code
    success = verify_code(phone_number, code, context, chat_id)
    
    if success:
        # Move to next phone or finish
        context.user_data['verification_index'] += 1
        
        if context.user_data['verification_index'] < len(phones):
            # Next phone
            next_phone = phones[context.user_data['verification_index']]
            session_name = f"session_{next_phone}"
            
            request_verification_code(next_phone, session_name, context, chat_id)
            
            return INPUT_VERIFICATION_CODE
        else:
            # All done
            update.message.reply_text(
                "✅ Semua akun berhasil login!\n\n"
                "📤 Silakan upload file VCF untuk memulai pengecekan."
            )
            return VCF
    else:
        # Verification failed, stay in same state
        return INPUT_VERIFICATION_CODE


def handle_vcf(update: Update, context: CallbackContext) -> int:
    """Handle VCF state (text input)"""
    text = update.message.text.strip()
    
    if text == "⬅️ Kembali":
        return start(update, context)
    else:
        update.message.reply_text("📤 Silakan kirim file VCF (.vcf)")
        return VCF


def handle_vcf_reupload(update: Update, context: CallbackContext) -> int:
    """Handler untuk upload ulang VCF"""
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    
    logger.info(f"handle_vcf_reupload called by user {user_id}")
    
    if not is_user_allowed(user_id):
        update.message.reply_text("❌ Anda tidak memiliki izin untuk menggunakan bot ini.")
        return ConversationHandler.END
    
    if update.message.document:
        return handle_vcf_file(update, context)
    else:
        active_session = context.user_data.get('active_session')
        if active_session:
            phone_number = active_session['phone_number']
            update.message.reply_text(
                f"📤 Nomor aktif: {phone_number}\n\n"
                f"Silakan kirim file VCF baru (.vcf)"
            )
        else:
            update.message.reply_text("📤 Silakan kirim file VCF (.vcf)")
        
        return VCF_REUPLOAD


def select_account_to_delete(update: Update, context: CallbackContext) -> int:
    """Select account to delete"""
    text = update.message.text.strip()
    
    if text == "⬅️ Kembali":
        return start(update, context)
    
    try:
        number_index = int(text.split(".")[0]) - 1
        existing_sessions = context.user_data.get('existing_sessions', [])
        
        if 0 <= number_index < len(existing_sessions):
            phone_number = existing_sessions[number_index]
            session_name = f"session_{phone_number}"
            
            # Delete session files
            session_file = f"sessions/{session_name}.session"
            session_journal = f"sessions/{session_name}.session-journal"
            
            for file_path in [session_file, session_journal]:
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                        logger.info(f"🗑️ Deleted: {file_path}")
                    except Exception as e:
                        logger.error(f"❌ Error deleting {file_path}: {e}")
            
            # Clear from active session if it's the same
            active_session = context.user_data.get('active_session')
            if active_session and active_session['phone_number'] == phone_number:
                del context.user_data['active_session']
                logger.info(f"🧹 Cleared active session for {phone_number}")
            
            update.message.reply_text(f"✅ Nomor {phone_number} berhasil dihapus!")
            return start(update, context)
        else:
            update.message.reply_text("❌ Pilihan tidak valid.")
            return SELECT_ACCOUNT_DELETE
            
    except:
        update.message.reply_text("❌ Format tidak valid.")
        return SELECT_ACCOUNT_DELETE


def handle_admin_menu(update: Update, context: CallbackContext) -> int:
    """Handle admin menu"""
    text = update.message.text.strip()
    user_id = update.effective_user.id
    
    if not is_admin(user_id):
        update.message.reply_text("❌ Access denied.")
        return start(update, context)
    
    if text == "➕ Tambah Staff":
        update.message.reply_text("👤 Masukkan User ID staff yang akan ditambahkan:")
        return ADD_USER
        
    elif text == "🗑️ Hapus Staff":
        staff_users = load_staff_users()
        if not staff_users:
            update.message.reply_text("❌ Tidak ada staff.")
            return start(update, context)
        
        message = "📋 Daftar Staff:\n\n"
        for i, staff_id in enumerate(staff_users, 1):
            message += f"{i}. User ID: {staff_id}\n"
        
        update.message.reply_text(message)
        update.message.reply_text("Masukkan nomor staff yang akan dihapus atau ketik 'batal':")
        
        context.user_data['staff_list'] = staff_users
        return DELETE_SINGLE_USER
        
    elif text == "📊 Lihat Statistik":
        existing_sessions = get_existing_sessions()
        staff_count = len(load_staff_users())
        admin_count = len(load_admin_users())
        
        with verification_lock:
            active_verifications = sum(len(reqs) for reqs in user_verification_requests.values())
        
        stats_message = f"""
📊 **STATISTIK BOT**

📱 Total nomor login: {len(existing_sessions)}
👥 Total staff: {staff_count}
👑 Total admin: {admin_count}
🔄 Active verifications: {active_verifications}

🕐 Server time: {time.strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        update.message.reply_text(stats_message)
        return start(update, context)
        
    elif text == "⬅️ Kembali":
        return start(update, context)
    
    else:
        update.message.reply_text("❌ Pilihan tidak valid.")
        return ADMIN_MENU


def add_user(update: Update, context: CallbackContext) -> int:
    """Add staff user"""
    text = update.message.text.strip()
    user_id = update.effective_user.id
    
    if not is_admin(user_id):
        update.message.reply_text("❌ Access denied.")
        return start(update, context)
    
    try:
        new_user_id = int(text)
        
        staff_users = load_staff_users()
        if new_user_id in staff_users:
            update.message.reply_text("⚠️ User sudah terdaftar sebagai staff.")
        else:
            staff_users.append(new_user_id)
            save_staff_users(staff_users)
            update.message.reply_text(f"✅ User {new_user_id} berhasil ditambahkan sebagai staff!")
        
        return start(update, context)
        
    except ValueError:
        update.message.reply_text("❌ User ID harus berupa angka.")
        return ADD_USER


def handle_delete_single_user(update: Update, context: CallbackContext) -> int:
    """Delete single staff user"""
    text = update.message.text.strip().lower()
    user_id = update.effective_user.id
    
    if not is_admin(user_id):
        update.message.reply_text("❌ Access denied.")
        return start(update, context)
    
    if text == 'batal':
        return start(update, context)
    
    try:
        staff_index = int(text) - 1
        staff_list = context.user_data.get('staff_list', [])
        
        if 0 <= staff_index < len(staff_list):
            staff_id = staff_list[staff_index]
            staff_users = load_staff_users()
            
            if staff_id in staff_users:
                staff_users.remove(staff_id)
                save_staff_users(staff_users)
                update.message.reply_text(f"✅ Staff {staff_id} berhasil dihapus!")
            else:
                update.message.reply_text("❌ Staff tidak ditemukan.")
        else:
            update.message.reply_text("❌ Nomor tidak valid.")
        
        return start(update, context)
        
    except ValueError:
        update.message.reply_text("❌ Input harus berupa angka.")
        return DELETE_SINGLE_USER


def cancel(update: Update, context: CallbackContext) -> int:
    """Cancel conversation"""
    update.message.reply_text("❌ Dibatalkan.")
    return start(update, context)


def stop_process(update: Update, context: CallbackContext):
    """Stop VCF processing"""
    user_id = update.effective_user.id
    
    # Set stop flag
    if 'current_vcf_process' in context.user_data:
        del context.user_data['current_vcf_process']
        update.message.reply_text("⏹️ Proses dihentikan.")
    else:
        update.message.reply_text("ℹ️ Tidak ada proses yang berjalan.")
    
    return start(update, context)


# ========== CALLBACK HANDLERS ==========

def multithreaded_button_callback(update: Update, context: CallbackContext) -> int:
    """Handle inline keyboard button callbacks"""
    query = update.callback_query
    user_id = query.from_user.id
    chat_id = query.message.chat_id
    
    with user_semaphores[user_id]:
        # Answer callback query
        max_answer_retries = 3
        for attempt in range(max_answer_retries):
            try:
                query.answer(timeout=10)
                logger.info(f"✅ Callback answered - User {user_id}: {query.data}")
                break
            except Exception as e:
                logger.error(f"❌ Error answering callback: {e}")
                if attempt == max_answer_retries - 1:
                    logger.warning(f"⚠️ Callback answer failed after retries")
                    time.sleep(0.5)
        
        context.user_data['user_id'] = user_id
        context.user_data['chat_id'] = chat_id
        
        if not is_user_allowed(user_id):
            try:
                query.edit_message_text(text="❌ Access denied.")
            except:
                context.bot.send_message(chat_id=chat_id, text="❌ Access denied.")
            return ConversationHandler.END
        
        callback_data = query.data
        logger.info(f"🔄 Processing callback: {callback_data} from user {user_id}")
        
        try:
            # Parse callback data
            if "_" in callback_data:
                parts = callback_data.split("_")
                action = parts[0]
                sub_action = parts[1] if len(parts) > 1 else ""
                timestamp = parts[-1] if len(parts) > 2 else ""
                
                # Handle continue
                if action == "continue":
                    if sub_action == "yes":
                        try:
                            query.edit_message_text(text="🔄 Melanjutkan proses...")
                        except:
                            context.bot.send_message(chat_id=chat_id, text="🔄 Melanjutkan proses...")
                        
                        def safe_continue():
                            time.sleep(0.5)
                            continue_vcf_process(context, True)
                        
                        threading.Thread(target=safe_continue, daemon=True).start()
                        return VCF_REUPLOAD
                        
                    elif sub_action == "no":
                        try:
                            query.edit_message_text(text="❌ Proses dihentikan.")
                        except:
                            context.bot.send_message(chat_id=chat_id, text="❌ Proses dihentikan.")
                        
                        continue_vcf_process(context, False)
                        time.sleep(1)
                        return start(None, context)
                
                # Handle change number
                elif action == "change":
                    if sub_action == "number":
                        try:
                            query.edit_message_text(text="📱 Memproses ganti nomor...")
                        except:
                            context.bot.send_message(chat_id=chat_id, text="📱 Memproses ganti nomor...")
                        
                        change_number_for_vcf(query, context)
                        return CHANGE_NUMBER
                
                # Handle back to menu
                elif action == "back":
                    try:
                        query.edit_message_text(text="⬅️ Kembali ke menu...")
                    except:
                        context.bot.send_message(chat_id=chat_id, text="⬅️ Kembali ke menu...")
                    
                    time.sleep(1)
                    return start(None, context)
                
                else:
                    logger.warning(f"🚨 Unhandled callback: {callback_data}")
                    try:
                        query.edit_message_text(text="❌ Opsi tidak dikenali.")
                    except:
                        context.bot.send_message(chat_id=chat_id, text="❌ Opsi tidak dikenali.")
                    
                    time.sleep(1)
                    return start(None, context)
            else:
                # Legacy callbacks without timestamp
                logger.info(f"🔄 Legacy callback: {callback_data}")
                
                if callback_data == "continue_yes":
                    return handle_continue_yes(query, context)
                elif callback_data == "continue_no":
                    return handle_continue_no(query, context)
                elif callback_data in ["change_number", "change_number_new_vcf"]:
                    return handle_change_number(query, context)
                elif callback_data == "back_to_menu":
                    return handle_back_to_menu(query, context)
                else:
                    return start(None, context)
                    
        except Exception as e:
            logger.error(f"🚨 Critical error: {e}")
            try:
                context.bot.send_message(
                    chat_id=chat_id,
                    text="❌ Terjadi kesalahan. Bot akan kembali ke menu..."
                )
                time.sleep(1)
                return start(None, context)
            except:
                pass
            return ConversationHandler.END


def handle_continue_yes(query, context):
    """Handle continue yes button"""
    chat_id = query.message.chat_id
    
    try:
        query.edit_message_text(text="🔄 Melanjutkan proses...")
    except:
        context.bot.send_message(chat_id=chat_id, text="🔄 Melanjutkan proses...")
    
    def safe_continue_process():
        try:
            time.sleep(0.5)
            continue_vcf_process(context, True)
        except Exception as e:
            logger.error(f"Error in continue process: {e}")
            context.bot.send_message(
                chat_id=chat_id,
                text="❌ Terjadi kesalahan. Silakan coba lagi."
            )
    
    threading.Thread(target=safe_continue_process, daemon=True).start()
    
    return VCF_REUPLOAD


def handle_continue_no(query, context):
    """Handle continue no button"""
    chat_id = query.message.chat_id
    
    try:
        query.edit_message_text(text="❌ Proses dihentikan.")
    except:
        context.bot.send_message(chat_id=chat_id, text="❌ Proses dihentikan.")
    
    continue_vcf_process(context, False)
    time.sleep(1)
    return start(None, context)


def handle_change_number(query, context):
    """Handle change number button"""
    chat_id = query.message.chat_id
    
    try:
        query.edit_message_text(text="📱 Memproses ganti nomor...")
    except:
        context.bot.send_message(chat_id=chat_id, text="📱 Memproses ganti nomor...")
    
    change_number_for_vcf(query, context)
    return CHANGE_NUMBER


def handle_back_to_menu(query, context):
    """Handle back to menu button"""
    chat_id = query.message.chat_id
    
    try:
        query.edit_message_text(text="⬅️ Kembali ke menu...")
    except:
        context.bot.send_message(chat_id=chat_id, text="⬅️ Kembali ke menu...")
    
    time.sleep(1)
    return start(None, context)


def continue_vcf_process(context, continue_choice):
    """Continue VCF processing based on user choice"""
    if 'chat_id' not in context.user_data:
        logger.error("Error: chat_id not found")
        return
    
    chat_id = context.user_data['chat_id']
    
    if 'current_vcf_process' not in context.user_data:
        context.bot.send_message(
            chat_id=chat_id, 
            text="❌ Session expired, please restart."
        )
        return
    
    if not continue_choice:
        context.bot.send_message(chat_id=chat_id, text="⏹️ Process stopped.")
        del context.user_data['current_vcf_process']
        return
    
    # Continue processing
    def safe_continue_thread():
        try:
            time.sleep(1)
            continue_vcf_process_thread(context)
        except Exception as e:
            logger.error(f"Error in continue thread: {e}")
            context.bot.send_message(
                chat_id=chat_id,
                text="❌ Error continuing process."
            )
    
    process_thread = threading.Thread(target=safe_continue_thread, daemon=True)
    process_thread.start()


def continue_vcf_process_thread(context):
    """Continue VCF processing in thread"""
    if 'chat_id' not in context.user_data:
        logger.error("Error: chat_id not found in thread")
        return
    
    chat_id = context.user_data['chat_id']
    
    try:
        asyncio.set_event_loop(asyncio.new_event_loop())
    except RuntimeError:
        pass
    
    if 'current_vcf_process' not in context.user_data:
        context.bot.send_message(chat_id=chat_id, text="❌ Session expired.")
        return
    
    # Get process data
    process_data = context.user_data['current_vcf_process']
    filename = process_data['filename']
    session_name = process_data['session_name']
    phone_number = process_data['phone_number']
    next_index = process_data['next_index']
    contacts = process_data['contacts']
    
    try:
        client = TelegramClient(f"sessions/{session_name}", API_ID, API_HASH)
        client.connect()
        
        if not client.is_user_authorized():
            context.bot.send_message(chat_id=chat_id, text="❌ Session expired, please login again.")
            return
        
        consecutive_not_found = 0
        should_stop = False

        for index, (name, phone) in enumerate(contacts[next_index-1:], start=next_index):
            if should_stop:
                context.bot.send_message(chat_id=chat_id, text="✅ Process stopped.")
                break
                
            first_name = name.split()[0] if name else "Kontak"
            last_name = " ".join(name.split()[1:]) if len(name.split()) > 1 else str(index)
            client_id = random.randint(100000, 999999)

            contact = InputPhoneContact(
                client_id=client_id,
                phone=phone,
                first_name=first_name,
                last_name=last_name
            )

            try:
                result = client(ImportContactsRequest([contact]))
                user = result.users[0] if result.users else None

                if user:
                    context.bot.send_message(chat_id=chat_id, text=f"✅ [{index}] {name} - {phone} Okeni.")
                    consecutive_not_found = 0
                else:
                    context.bot.send_message(chat_id=chat_id, text=f"⚠️ [{index}] {name} - {phone} jelek")
                    consecutive_not_found += 1
                    logger.info(f"Consecutive not found: {consecutive_not_found}/{MAX_CONSECUTIVE_NOT_FOUND}")
                
                if consecutive_not_found >= MAX_CONSECUTIVE_NOT_FOUND:
                    logger.info("Reached max, showing keyboard")
                    
                    context.user_data['current_vcf_process'] = {
                        'filename': filename,
                        'session_name': session_name,
                        'phone_number': phone_number,
                        'next_index': index + 1,
                        'contacts': contacts
                    }

                    try:
                        keyboard = [
                            [InlineKeyboardButton("Ya", callback_data="continue_yes")],
                            [InlineKeyboardButton("Ganti Nomor", callback_data="change_number")],
                            [InlineKeyboardButton("Tidak", callback_data="continue_no")]
                        ]
                        reply_markup = InlineKeyboardMarkup(keyboard)

                        time.sleep(1)
                        context.bot.send_message(
                            chat_id=chat_id,
                            text=f"⚠️ {MAX_CONSECUTIVE_NOT_FOUND} kontak tidak ditemukan.\n\n"
                                f"📱 Nomor: {phone_number}\n"
                                f"📊 Kontak: {index}\n\n"
                                f"Lanjutkan?",
                            reply_markup=reply_markup
                        )
                        logger.info("Keyboard sent")
                        
                    except Exception as e:
                        logger.error(f"Error sending keyboard: {e}")
                    
                    client.disconnect()
                    return
                        
                time.sleep(7)
            except Exception as e:
                context.bot.send_message(chat_id=chat_id, text=f"❌ [{index}] Error: {name}: {e}")

        client.disconnect()
        
        # 🔥 TAMBAHAN: Show summary dengan history jika ada ganti nomor
        history = context.user_data.get('number_change_history', [])
        
        summary = "✅ PROSES SELESAI!\n\n"
        
        if history:
            summary += "🔄 Riwayat Ganti Nomor:\n"
            for i, record in enumerate(history, 1):
                summary += f"{i}. {record['phone']} (sampai kontak #{record['stopped_at_index']})\n"
            
            # Nomor terakhir
            final_phone = context.user_data.get('current_vcf_process', {}).get('phone_number', 'Unknown')
            summary += f"{len(history)+1}. {final_phone} (selesai) ✅\n"
            summary += f"\nTotal ganti nomor: {len(history)} kali"
            
            # Cleanup history setelah selesai
            context.user_data['number_change_history'] = []
        else:
            summary += "✅ Proses selesai tanpa ganti nomor"
        
        context.bot.send_message(chat_id=chat_id, text=summary)
        
    except Exception as e:
        logger.error(f"Error in continue thread: {e}")
        try:
            client.disconnect()
        except:
            pass
        context.bot.send_message(chat_id=chat_id, text=f"❌ Error: {e}")


def change_number_for_vcf(query, context):
    """
    🔥 FIXED: Minta INPUT nomor baru (bukan pilih dari list)
    Flow: User input nomor → Verifikasi (jika perlu) → Lanjut proses
    """
    chat_id = query.message.chat_id
    user_id = query.from_user.id
    
    # Initialize number change history jika belum ada
    if 'number_change_history' not in context.user_data:
        context.user_data['number_change_history'] = []
    
    # Check maximum limit
    history = context.user_data['number_change_history']
    if len(history) >= MAX_NUMBER_CHANGES:
        try:
            query.edit_message_text(
                text=f"❌ BATAS MAKSIMUM TERCAPAI\n\n"
                     f"Anda sudah ganti nomor {MAX_NUMBER_CHANGES} kali.\n\n"
                     f"📊 Nomor yang sudah dicoba:\n" +
                     "\n".join([f"{i+1}. {h['phone']} (sampai kontak #{h['stopped_at_index']})" 
                               for i, h in enumerate(history)]) +
                     f"\n\n💡 Kemungkinan file VCF memiliki banyak kontak yang:\n"
                     f"• Tidak pakai Telegram\n"
                     f"• Nomor tidak aktif\n"
                     f"• Format salah\n\n"
                     f"Pilihan:\n"
                     f"1. Lanjutkan dengan nomor saat ini → ketik 'lanjut'\n"
                     f"2. Hentikan proses → ketik 'stop'\n"
                     f"3. Kembali ke menu → /start"
            )
        except:
            context.bot.send_message(
                chat_id=chat_id,
                text=f"❌ BATAS MAKSIMUM: Sudah {MAX_NUMBER_CHANGES}x ganti nomor.\n"
                     f"Ketik 'lanjut', 'stop', atau /start"
            )
        
        return CHANGE_NUMBER
    
    # Warning system based on change count
    warning_message = ""
    if len(history) == 1:
        warning_message = "\nℹ️ INFO: Ini ganti nomor kedua Anda."
    elif len(history) == 2:
        warning_message = "\n⚠️ WARNING: Anda sudah ganti nomor 3 kali."
    elif len(history) == 3:
        warning_message = "\n🚨 CAUTION: Sudah 4x ganti. Pertimbangkan kualitas file VCF."
    elif len(history) >= 4:
        warning_message = "\n🔴 ALERT: Ini ganti nomor terakhir!"
    
    # Show input prompt
    try:
        query.edit_message_text(
            text=f"📱 GANTI NOMOR{warning_message}\n\n"
                 f"Masukkan nomor BARU yang ingin digunakan untuk melanjutkan pengecekan.\n\n"
                 f"Format: +62xxxxxxxxxx\n\n"
                 f"Atau ketik 'batal' untuk kembali."
        )
    except:
        context.bot.send_message(
            chat_id=chat_id,
            text=f"📱 GANTI NOMOR{warning_message}\n\n"
                 f"Masukkan nomor BARU:\n"
                 f"Format: +62xxxxxxxxxx\n\n"
                 f"Ketik 'batal' untuk kembali."
        )
    
    # Set flags untuk handler berikutnya
    context.user_data['waiting_for_new_number'] = True
    context.user_data['change_number_source'] = 'vcf_process'
    
    return INPUT_NEW_NUMBER



def handle_new_number_input(update: Update, context: CallbackContext) -> int:
    """
    🔥 NEW: Handler untuk input nomor baru dari user
    """
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    text = update.message.text.strip()
    
    # Check batal
    if text.lower() == 'batal':
        update.message.reply_text("❌ Dibatalkan.")
        return start(update, context)
    
    # Check lanjut (untuk case max limit reached)
    if text.lower() == 'lanjut':
        if 'current_vcf_process' in context.user_data:
            update.message.reply_text("🔄 Melanjutkan proses dengan nomor saat ini...")
            
            threading.Thread(
                target=continue_vcf_process_thread,
                args=(context,),
                daemon=True
            ).start()
            
            return VCF_REUPLOAD
        else:
            update.message.reply_text("❌ Tidak ada proses aktif.")
            return start(update, context)
    
    # Validate format nomor
    if not text.startswith('+'):
        update.message.reply_text(
            "❌ Format salah! Nomor harus diawali dengan +\n"
            "Contoh: +6281234567890\n\n"
            "Coba lagi atau ketik 'batal':"
        )
        return INPUT_NEW_NUMBER
    
    # Validate panjang
    if len(text) < 10:
        update.message.reply_text(
            "❌ Nomor terlalu pendek!\n"
            "Coba lagi atau ketik 'batal':"
        )
        return INPUT_NEW_NUMBER
    
    phone_number = text
    
    # 🔥 DUPLICATE DETECTION: Check apakah nomor ini sudah dicoba
    history = context.user_data.get('number_change_history', [])
    used_numbers = [record['phone'] for record in history]
    
    # Add current number juga
    current_phone = context.user_data.get('current_vcf_process', {}).get('phone_number')
    if current_phone:
        used_numbers.append(current_phone)
    
    if phone_number in used_numbers:
        update.message.reply_text(
            f"⚠️ NOMOR SUDAH DICOBA!\n\n"
            f"Nomor {phone_number} sudah digunakan sebelumnya dalam proses ini.\n\n"
            f"📊 Nomor yang sudah dicoba:\n" +
            "\n".join([f"• {num}" for num in used_numbers]) +
            f"\n\n💡 Masukkan nomor LAIN yang belum dicoba.\n"
            f"Atau ketik 'batal' untuk kembali."
        )
        return INPUT_NEW_NUMBER
    
    # 🔥 RATE LIMIT CHECK: Check timing antara login
    if history:
        last_change = history[-1]['timestamp']
        time_since_last = time.time() - last_change
        
        if time_since_last < MIN_CHANGE_INTERVAL:
            remaining = int(MIN_CHANGE_INTERVAL - time_since_last)
            
            update.message.reply_text(
                f"⏱️ COOLDOWN AKTIF\n\n"
                f"Untuk menghindari rate limit dari Telegram, "
                f"mohon tunggu {remaining} detik sebelum ganti nomor lagi.\n\n"
                f"⏳ Waktu tersisa: {remaining // 60}m {remaining % 60}s\n\n"
                f"Atau ketik 'batal' untuk kembali."
            )
            
            # Schedule retry check
            time.sleep(2)
            return INPUT_NEW_NUMBER
    
    session_name = f"session_{phone_number}"
    session_file = f"sessions/{session_name}.session"
    
    # Check apakah nomor ini sudah login sebelumnya
    if os.path.exists(session_file):
        # ✅ Sudah login - langsung pakai
        update.message.reply_text(
            f"✅ Nomor {phone_number} sudah login sebelumnya.\n"
            f"Menggunakan session yang ada...\n\n"
            f"🔄 Melanjutkan proses pengecekan..."
        )
        
        # Record history BEFORE continuing
        if 'current_vcf_process' in context.user_data:
            old_phone = context.user_data['current_vcf_process']['phone_number']
            old_index = context.user_data['current_vcf_process'].get('next_index', 1) - 1
            
            context.user_data['number_change_history'].append({
                'phone': old_phone,
                'stopped_at_index': old_index,
                'timestamp': time.time()
            })
        
        # Update context
        context.user_data['active_session'] = {
            'phone_number': phone_number,
            'session_name': session_name
        }
        
        # Update VCF process
        if 'current_vcf_process' in context.user_data:
            context.user_data['current_vcf_process']['phone_number'] = phone_number
            context.user_data['current_vcf_process']['session_name'] = session_name
            
            # Continue processing
            time.sleep(1)
            threading.Thread(
                target=continue_vcf_process_thread,
                args=(context,),
                daemon=True
            ).start()
            
            return VCF_REUPLOAD
        else:
            # No active process, just update active session
            update.message.reply_text(
                f"📤 Nomor aktif sekarang: {phone_number}\n"
                f"Silakan upload file VCF."
            )
            return VCF
    
    else:
        # ❌ Belum login - perlu verifikasi
        update.message.reply_text(
            f"📱 Nomor {phone_number} belum terdaftar.\n"
            f"Mengirim kode verifikasi..."
        )
        
        # Save nomor untuk proses verifikasi
        context.user_data['pending_new_number'] = phone_number
        context.user_data['pending_new_session'] = session_name
        
        # Request verification code
        success = request_verification_code(
            phone_number, 
            session_name, 
            context, 
            chat_id
        )
        
        if success:
            return INPUT_VERIFICATION_CODE_FOR_CHANGE
        else:
            update.message.reply_text(
                "❌ Gagal mengirim kode verifikasi.\n"
                "Coba lagi atau hubungi admin."
            )
            return start(update, context)


def handle_verification_code_for_change(update: Update, context: CallbackContext) -> int:
    """
    🔥 NEW: Handle verifikasi kode untuk nomor baru saat ganti nomor
    """
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    code = update.message.text.strip()
    
    # Get pending number
    phone_number = context.user_data.get('pending_new_number')
    session_name = context.user_data.get('pending_new_session')
    
    if not phone_number:
        update.message.reply_text("❌ Session expired. Silakan /start ulang.")
        return start(update, context)
    
    # Verify code
    success = verify_code(phone_number, code, context, chat_id)
    
    if success:
        # ✅ Verification berhasil!
        update.message.reply_text(
            f"✅ Login berhasil untuk {phone_number}!\n\n"
            f"🔄 Melanjutkan proses pengecekan dengan nomor baru..."
        )
        
        # Record history BEFORE continuing
        if 'current_vcf_process' in context.user_data:
            old_phone = context.user_data['current_vcf_process']['phone_number']
            old_index = context.user_data['current_vcf_process'].get('next_index', 1) - 1
            
            if 'number_change_history' not in context.user_data:
                context.user_data['number_change_history'] = []
            
            context.user_data['number_change_history'].append({
                'phone': old_phone,
                'stopped_at_index': old_index,
                'timestamp': time.time()
            })
        
        # Update VCF process dengan nomor baru
        if 'current_vcf_process' in context.user_data:
            context.user_data['current_vcf_process']['phone_number'] = phone_number
            context.user_data['current_vcf_process']['session_name'] = session_name
            
            # Cleanup pending data
            del context.user_data['pending_new_number']
            del context.user_data['pending_new_session']
            
            # Continue processing dengan nomor baru
            time.sleep(1)
            threading.Thread(
                target=continue_vcf_process_thread,
                args=(context,),
                daemon=True
            ).start()
            
            return VCF_REUPLOAD
        else:
            # No active VCF process
            update.message.reply_text(
                f"📤 Nomor aktif sekarang: {phone_number}\n"
                f"Silakan upload file VCF."
            )
            
            # Cleanup pending data
            if 'pending_new_number' in context.user_data:
                del context.user_data['pending_new_number']
            if 'pending_new_session' in context.user_data:
                del context.user_data['pending_new_session']
            
            return VCF
    
    else:
        # ❌ Verification gagal
        # User tetap di state ini, bisa coba lagi
        return INPUT_VERIFICATION_CODE_FOR_CHANGE


def handle_change_number_choice(update: Update, context: CallbackContext) -> int:
    """
    ⚠️ DEPRECATED: Fungsi ini sudah tidak dipakai lagi
    Diganti dengan handle_new_number_input()
    Tapi tetap di-keep untuk backward compatibility
    """
    # Redirect ke handler baru
    return handle_new_number_input(update, context)


def handle_fallback_all_states(update: Update, context: CallbackContext) -> int:
    """Fallback handler for unhandled messages"""
    logger.warning(f"Fallback handler triggered: {update.message.text if update.message else 'No message'}")
    
    if update.message:
        update.message.reply_text(
            "❌ Perintah tidak dikenali.\n"
            "Gunakan /start untuk kembali ke menu utama."
        )
    
    return start(update, context)


def handle_notification_message(update: Update, context: CallbackContext) -> int:
    """Handle notification message (if needed)"""
    # Placeholder for future notification handling
    return start(update, context)


# ========== CONVERSATION HANDLER SETUP ==========

def create_conversation_handler():
    """Create conversation handler"""
    return ConversationHandler(
        entry_points=[CommandHandler('start', start)],
        states={
            MENU: [
                MessageHandler(Filters.text & ~Filters.command, handle_menu),
                CallbackQueryHandler(multithreaded_button_callback),
            ],
            ASK_NUM_ACCOUNTS: [
                MessageHandler(Filters.text & ~Filters.command, ask_num_accounts),
                CallbackQueryHandler(multithreaded_button_callback)
            ],
            INPUT_PHONES: [
                MessageHandler(Filters.text & ~Filters.command, input_phones),
                CallbackQueryHandler(multithreaded_button_callback)
            ],
            INPUT_VERIFICATION_CODE: [
                MessageHandler(Filters.text & ~Filters.command, input_verification_code),
                CallbackQueryHandler(multithreaded_button_callback)
            ],
            VCF: [
                MessageHandler(Filters.document, handle_vcf_file),
                MessageHandler(Filters.text & ~Filters.command, handle_vcf),
                CallbackQueryHandler(multithreaded_button_callback)
            ],
            VCF_SELECT: [
                MessageHandler(Filters.text & ~Filters.command, handle_vcf_selection),
                CallbackQueryHandler(multithreaded_button_callback)
            ],
            VCF_REUPLOAD: [
                MessageHandler(Filters.document, handle_vcf_file),
                MessageHandler(Filters.text & ~Filters.command, handle_vcf_reupload),
                CallbackQueryHandler(multithreaded_button_callback)
            ],
            CHANGE_NUMBER: [
                MessageHandler(Filters.text & ~Filters.command, handle_change_number_choice),
                CallbackQueryHandler(multithreaded_button_callback)
            ],
            INPUT_NEW_NUMBER: [
                MessageHandler(Filters.text & ~Filters.command, handle_new_number_input),
                CallbackQueryHandler(multithreaded_button_callback)
            ],
            INPUT_VERIFICATION_CODE_FOR_CHANGE: [
                MessageHandler(Filters.text & ~Filters.command, handle_verification_code_for_change),
                CallbackQueryHandler(multithreaded_button_callback)
            ],
            SELECT_ACCOUNT_DELETE: [
                MessageHandler(Filters.text & ~Filters.command, select_account_to_delete),
                CallbackQueryHandler(multithreaded_button_callback)
            ],
            ADMIN_MENU: [
                MessageHandler(Filters.text & ~Filters.command, handle_admin_menu),
                CallbackQueryHandler(multithreaded_button_callback)
            ],
            ADD_USER: [
                MessageHandler(Filters.text & ~Filters.command, add_user),
                CallbackQueryHandler(multithreaded_button_callback)
            ],
            DELETE_SINGLE_USER: [
                MessageHandler(Filters.text & ~Filters.command, handle_delete_single_user),
                CallbackQueryHandler(multithreaded_button_callback)
            ],
            WAIT_FOR_NOTIFICATION_MESSAGE: [
                MessageHandler(Filters.text & ~Filters.command, handle_notification_message)
            ],
        },
        fallbacks=[
            CommandHandler('cancel', cancel),
            CommandHandler('start', start),
            CommandHandler('stop', stop_process),
            MessageHandler(Filters.all, handle_fallback_all_states)
        ],
        allow_reentry=True,
        per_chat=True,
        per_user=True,
    )


# ========== ERROR HANDLER ==========

def error_handler(update, context):
    """Log errors"""
    logger.warning('Update "%s" caused error "%s"', update, context.error)
    
    if update and update.effective_chat:
        try:
            context.bot.send_message(
                chat_id=update.effective_chat.id,
                text="❌ Terjadi kesalahan. Silakan /start untuk mulai ulang."
            )
        except:
            pass


# ========== MAIN FUNCTION ==========

start_time = time.time()

def main():
    """Main bot function"""
    logger.info("🚀 Starting bot...")
    
    # Initialize admin
    initialize_admin()
    
    # Create updater
    global updater
    updater = Updater(BOT_TOKEN, use_context=True)
    dp = updater.dispatcher
    
    # Add conversation handler
    conv_handler = create_conversation_handler()
    dp.add_handler(conv_handler)
    
    # Add error handler
    dp.add_error_handler(error_handler)
    
    # Start keep-alive thread
    def improved_keep_alive_handler():
        """Keep-alive thread"""
        consecutive_failures = 0
        
        while True:
            try:
                response = requests.get(
                    'https://api.telegram.org/bot' + BOT_TOKEN + '/getMe', 
                    timeout=30
                )
                
                if response.status_code == 200:
                    consecutive_failures = 0
                    logger.info("✅ Keep-alive ping successful")
                else:
                    consecutive_failures += 1
                    logger.warning(f"⚠️ Keep-alive failed: {response.status_code}")
                
            except Exception as e:
                consecutive_failures += 1
                logger.error(f"❌ Keep-alive error: {e}")
                
                if consecutive_failures >= 5:
                    logger.critical("🚨 Too many failures")
                    consecutive_failures = 0
            
            sleep_time = 60 if consecutive_failures == 0 else min(120, 60 + (consecutive_failures * 10))
            time.sleep(sleep_time)

    keep_alive_thread = threading.Thread(target=improved_keep_alive_handler, daemon=True)
    keep_alive_thread.start()
    logger.info("🔄 Keep-alive thread started")

    # Start watchdog thread
    def improved_watchdog_handler():
        """Watchdog thread"""
        last_response_time = time.time()
        restart_count = 0
        
        while True:
            try:
                response = requests.get(
                    'https://api.telegram.org/bot' + BOT_TOKEN + '/getWebhookInfo', 
                    timeout=15
                )
                
                if response.status_code == 200:
                    last_response_time = time.time()
                    restart_count = 0
                else:
                    if time.time() - last_response_time > 300:
                        restart_count += 1
                        logger.warning(f"🚨 Bot unresponsive (restart #{restart_count})")
                        
                        try:
                            updater.stop()
                            time.sleep(10)
                            
                            updater.start_polling(
                                timeout=60,
                                poll_interval=1.0,
                                drop_pending_updates=True,
                                bootstrap_retries=10,
                                read_latency=5.0
                            )
                            
                            last_response_time = time.time()
                            logger.info(f"✅ Bot restarted (attempt #{restart_count})")
                            
                        except Exception as restart_error:
                            logger.error(f"❌ Restart error: {restart_error}")
                            
                            if restart_count >= 3:
                                logger.critical("🚨 Multiple restart failures")
                                time.sleep(300)
                                restart_count = 0
                                
            except Exception as e:
                logger.error(f"❌ Watchdog error: {e}")
            
            time.sleep(120)

    watchdog_thread = threading.Thread(target=improved_watchdog_handler, daemon=True)
    watchdog_thread.start()
    logger.info("🐕 Watchdog thread started")

    # Start cleanup thread
    def periodic_cleanup():
        """Periodic cleanup thread"""
        while True:
            try:
                current_time = time.time()
                
                with verification_lock:
                    users_to_cleanup = []
                    total_cleaned = 0
                    
                    user_items = list(user_verification_requests.items())
                    
                    for user_id, user_requests in user_items:
                        phones_to_cleanup = []
                        
                        phone_items = list(user_requests.items())
                        for phone, request_data in phone_items:
                            time_requested = request_data.get('time_requested', 0)
                            if current_time - time_requested > 1800:
                                phones_to_cleanup.append(phone)
                        
                        for phone in phones_to_cleanup:
                            try:
                                request_data = user_requests.get(phone)
                                if request_data and 'client' in request_data:
                                    client = request_data['client']
                                    if client and hasattr(client, 'is_connected'):
                                        if client.is_connected():
                                            client.disconnect()
                                            logger.debug(f"🔌 Disconnected expired client: user {user_id}, phone {phone}")
                            except Exception as disconnect_error:
                                logger.error(f"❌ Disconnect error: {disconnect_error}")
                            
                            try:
                                if phone in user_requests:
                                    del user_requests[phone]
                                    total_cleaned += 1
                                    logger.info(f"🧹 Cleaned expired request: user {user_id}, phone {phone}")
                            except Exception as delete_error:
                                logger.error(f"❌ Delete error: {delete_error}")
                        
                        if not user_requests:
                            users_to_cleanup.append(user_id)
                    
                    for user_id in users_to_cleanup:
                        try:
                            if user_id in user_verification_requests:
                                del user_verification_requests[user_id]
                                logger.info(f"🗑️ Removed empty user requests: {user_id}")
                        except Exception as user_delete_error:
                            logger.error(f"❌ User delete error: {user_delete_error}")
                    
                    active_users = len(user_verification_requests)
                    total_requests = sum(len(reqs) for reqs in user_verification_requests.values())
                    
                    logger.info(f"🧹 Cleanup: Cleaned {total_cleaned}, Active users {active_users}, Total requests {total_requests}")
                    
                    if active_users > 800:
                        logger.warning(f"⚠️ HIGH USER COUNT: {active_users}")
                    if total_requests > 1000:
                        logger.warning(f"⚠️ HIGH REQUEST COUNT: {total_requests}")
                
            except Exception as e:
                logger.error(f"❌ Cleanup error: {e}")
                import traceback
                logger.error(f"🔍 Traceback: {traceback.format_exc()}")
            
            try:
                time.sleep(1800)  # 30 minutes
            except KeyboardInterrupt:
                logger.info("🛑 Cleanup stopped")
                break
            except Exception as sleep_error:
                logger.error(f"❌ Sleep error: {sleep_error}")
                time.sleep(60)

    cleanup_thread = threading.Thread(target=periodic_cleanup, daemon=True)
    cleanup_thread.start()
    logger.info("🧹 Cleanup thread started")

    # Start bot polling
    try:
        logger.info("🚀 Starting bot polling...")
        updater.start_polling(
            timeout=60,
            poll_interval=1.0,
            drop_pending_updates=True,
            bootstrap_retries=15,
            read_latency=3.0,
            allowed_updates=None,
        )
        
        logger.info("✅ Bot started successfully!")
        logger.info(f"📊 Configuration:")
        logger.info(f"   - Timeout: 60s")
        logger.info(f"   - Poll interval: 1.0s")
        
    except Exception as e:
        logger.critical(f"🚨 Failed to start bot: {e}")
        raise

    # Run bot until stopped
    try:
        updater.idle()
    except KeyboardInterrupt:
        logger.info("👋 Bot stopped by user")
    except Exception as e:
        logger.error(f"❌ Bot stopped: {e}")
    finally:
        logger.info("🧹 Cleaning up...")
        
        with verification_lock:
            for user_id in list(user_verification_requests.keys()):
                try:
                    cleanup_user_verification(user_id)
                except Exception as cleanup_error:
                    logger.error(f"❌ Cleanup error for user {user_id}: {cleanup_error}")
        
        logger.info("✅ Cleanup completed")


if __name__ == '__main__':
    main()