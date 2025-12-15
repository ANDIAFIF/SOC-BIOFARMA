import asyncio
import json
import os
import logging
from pathlib import Path

from telethon import TelegramClient
from telethon.errors import (
    SessionPasswordNeededError,
    FloodWaitError,
    PeerIdInvalidError,
)
from telethon.tl.types import InputPhoneContact
from telethon.tl.functions.contacts import ImportContactsRequest, DeleteContactsRequest

# ====================================================
# LOGGER SETTING
# ====================================================
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# ====================================================
# KONFIGURASI TELEGRAM
# ====================================================
API_ID = 24866155  # Ganti dengan API_ID Anda dari https://my.telegram.org
API_HASH = "1356c13f14e1c92fdd2f8de5c7f38861"  # Ganti dengan API_HASH Anda

# Session folder
SESSION_DIR = "sessions"
if not os.path.exists(SESSION_DIR):
    os.makedirs(SESSION_DIR)

# ====================================================
# FUNGSI UNTUK MEMBACA FILE
# ====================================================
def read_numbers(filepath):
    """Baca file nomor telepon"""
    filepath = Path(filepath)
    
    if not filepath.exists():
        logger.error(f"File tidak ditemukan: {filepath}")
        return None
    
    numbers = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            numbers = [line.strip() for line in f if line.strip()]
        
        logger.info(f"Berhasil membaca {len(numbers)} nomor dari {filepath.name}")
        return numbers
    
    except Exception as e:
        logger.error(f"Error membaca file: {e}")
        return None

# ====================================================
# FUNGSI CEK NOMOR DENGAN IMPORT
# ====================================================
async def check_phone_number(client, phone, retry=0):
    """
    Cek apakah nomor telepon terdaftar di Telegram
    dengan cara import ke kontak lalu cek
    """
    if retry > 3:
        return {'phone': phone, 'status': 'error', 'registered': False}
    
    try:
        # Buat InputPhoneContact
        contact = InputPhoneContact(
            client_id=0,
            phone=phone,
            first_name='Check',
            last_name=''
        )
        
        # Import kontak
        result = await client(ImportContactsRequest([contact]))
        
        # Cek apakah user ditemukan
        if result.imported and len(result.users) > 0:
            user = result.users[0]
            return {
                'phone': phone,
                'status': 'registered',
                'user_id': user.id,
                'first_name': getattr(user, 'first_name', 'N/A'),
                'registered': True
            }
        else:
            return {
                'phone': phone,
                'status': 'not_registered',
                'registered': False
            }
    
    except FloodWaitError as e:
        # Jika rate limit, tunggu dan retry
        wait_time = min(e.seconds, 60)  # max 60 detik
        logger.warning(f"FloodWait {wait_time}s untuk {phone}, tunggu...")
        await asyncio.sleep(wait_time)
        return await check_phone_number(client, phone, retry + 1)
    
    except PeerIdInvalidError:
        return {
            'phone': phone,
            'status': 'not_registered',
            'registered': False
        }
    
    except Exception as e:
        logger.warning(f"Error cek {phone}: {e}")
        return {
            'phone': phone,
            'status': 'error',
            'error': str(e),
            'registered': False
        }

# ====================================================
# FUNGSI SAVE HASIL
# ====================================================
def save_results(results, output_file="phone_check_results.json"):
    """Simpan hasil ke file JSON"""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        logger.info(f"Hasil disimpan ke {output_file}")
    except Exception as e:
        logger.error(f"Error menyimpan hasil: {e}")

# ====================================================
# FUNGSI MAIN
# ====================================================
async def main():
    print("\n" + "="*60)
    print("TELEGRAM PHONE NUMBER CHECKER")
    print("="*60 + "\n")
    
    # Input file nomor
    while True:
        file_input = input("📁 Masukkan nama file nomor (txt): ").strip()
        
        if not file_input:
            logger.error("Nama file tidak boleh kosong!")
            continue
        
        if not os.path.exists(file_input):
            file_input = os.path.join(os.getcwd(), file_input)
        
        if os.path.exists(file_input):
            break
        else:
            logger.error(f"File tidak ditemukan: {file_input}")
    
    # Baca nomor
    numbers = read_numbers(file_input)
    if not numbers:
        logger.error("Tidak ada nomor untuk dicek!")
        return
    
    print(f"\n📞 Total nomor: {len(numbers)}")
    
    # Setup client Telegram
    session_name = os.path.join(SESSION_DIR, "telegram_phone_checker")
    client = TelegramClient(session_name, API_ID, API_HASH)
    
    try:
        await client.connect()
        
        # Cek apakah sudah authorized
        if not await client.is_user_authorized():
            print("\nBelum login. Proses login...")
            
            # Minta nomor login
            phone = input("📱 Masukkan nomor login Telegram (+62...): ").strip()
            
            try:
                await client.send_code_request(phone)
            except Exception as e:
                logger.error(f"Gagal mengirim kode: {e}")
                return
            
            # Minta OTP
            code = input("🔑 Masukkan kode OTP: ").strip()
            try:
                await client.sign_in(phone=phone, code=code)
            except SessionPasswordNeededError:
                # Jika 2FA aktif
                pwd = input("🔒 Masukkan password 2FA: ").strip()
                try:
                    await client.sign_in(password=pwd)
                except Exception as e:
                    logger.error(f"Gagal login: {e}")
                    return
            except Exception as e:
                logger.error(f"Gagal verifikasi OTP: {e}")
                return
        
        # Tampilkan akun yang login
        me = await client.get_me()
        print(f"\n👤 Login sebagai: {getattr(me, 'first_name', 'N/A')}")
        print(f"├─ Phone: {getattr(me, 'phone', 'N/A')}")
        print(f"└─ User ID: {me.id}\n")
        
        # Mulai cek nomor
        print(f"🔍 Mulai cek {len(numbers)} nomor...\n")
        
        results = []
        registered_count = 0
        not_registered_count = 0
        error_count = 0
        
        for i, phone in enumerate(numbers, 1):
            print(f"[{i}/{len(numbers)}] Mengecek: {phone}...", end=" ", flush=True)
            
            result = await check_phone_number(client, phone)
            results.append(result)
            
            if result['registered']:
                print(f"✓ TERDAFTAR (ID: {result.get('user_id', 'N/A')})")
                registered_count += 1
            elif result['status'] == 'not_registered':
                print(f"✗ TIDAK TERDAFTAR")
                not_registered_count += 1
            else:
                print(f"⚠ ERROR")
                error_count += 1
            
            # Delay untuk menghindari rate limit
            await asyncio.sleep(2)
        
        # Ringkasan
        print("\n" + "="*60)
        print("📊 HASIL PENGECEKAN")
        print("="*60)
        print(f"✓ Terdaftar: {registered_count}")
        print(f"✗ Tidak Terdaftar: {not_registered_count}")
        print(f"⚠ Error/Tidak Bisa Dicek: {error_count}")
        print("="*60 + "\n")
        
        # Simpan hasil
        save_results(results, "phone_check_results.json")
        
        # Tampilkan nomor yang terdaftar
        registered = [r for r in results if r['registered']]
        if registered:
            print("✓ NOMOR TERDAFTAR:")
            for item in registered:
                print(f"  • {item['phone']} (ID: {item.get('user_id', 'N/A')})")
        
        # Tampilkan nomor yang tidak terdaftar
        not_registered = [r for r in results if r['status'] == 'not_registered']
        if not_registered:
            print("\n✗ NOMOR TIDAK TERDAFTAR:")
            for item in not_registered[:10]:  # Show first 10
                print(f"  • {item['phone']}")
            if len(not_registered) > 10:
                print(f"  ... dan {len(not_registered) - 10} nomor lagi")
    
    finally:
        await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
