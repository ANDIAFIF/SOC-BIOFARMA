import asyncio
import csv
import json
import os
import logging
from pathlib import Path

from telethon import TelegramClient
from telethon.errors import SessionPasswordNeededError
from telethon.tl.functions.contacts import ImportContactsRequest, DeleteContactsRequest
from telethon.tl.types import InputPhoneContact

# ====================================================
# LOGGER
# ====================================================
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# ====================================================
# API TELEGRAM
# ====================================================
API_ID = 16528366
API_HASH = "ca9dc45f1a383b6b084e48cf2f1f784c"

SESSION_DIR = "sessions"
os.makedirs(SESSION_DIR, exist_ok=True)

# ====================================================
# BACA FILE NOMOR
# ====================================================
def read_phone_file(filepath):
    filepath = Path(filepath)

    if not filepath.exists():
        logger.error(f"File tidak ditemukan: {filepath}")
        return None

    if filepath.suffix.lower() == ".txt":
        return [line.strip() for line in open(filepath) if line.strip()]

    if filepath.suffix.lower() == ".csv":
        return [row[0].strip() for row in csv.reader(open(filepath))]

    if filepath.suffix.lower() == ".json":
        js = json.load(open(filepath))
        if isinstance(js, list):
            return js
        if isinstance(js, dict):
            return list(js.values())

    logger.error("Gunakan TXT / CSV / JSON")
    return None

# ====================================================
# CEK NOMOR TERDAFTAR — AKURASI TINGGI
# ====================================================
async def check_phone_registered(client, phone_number):
    try:
        # client_id harus unik agar Telegram treat sebagai real contact
        unique_id = abs(hash(phone_number)) % (10**10)

        contact = InputPhoneContact(
            client_id=unique_id,
            phone=phone_number,
            first_name=".",   # dummy agar tidak tampil "Check"
            last_name=""
        )

        # Import: "lookup"
        result = await client(ImportContactsRequest([contact]))

        # Jika user ditemukan
        if result.users:
            user = result.users[0]

            # Hapus kontak agar bersih
            try:
                await client(DeleteContactsRequest(id=[user.id]))
            except:
                pass

            return {
                "phone": phone_number,
                "status": "registered",
                "user_id": user.id,
                "first_name": user.first_name or "-",
                "last_name": user.last_name or "-"
            }

        # Tidak ditemukan user
        return {
            "phone": phone_number,
            "status": "not_registered"
        }

    except Exception as e:
        return {
            "phone": phone_number,
            "status": "error",
            "error": str(e)
        }

# ====================================================
# INPUT NOMOR LOGIN
# ====================================================
def input_login_numbers():
    phones = []
    print("\nMasukkan nomor login Telegram satu per satu.")
    print("Gunakan format +62xxxx")
    print("Ketik 'done' jika selesai.\n")

    while True:
        p = input("Nomor Login / done: ").strip()
        if p.lower() == "done":
            break
        if p:
            phones.append(p)

    return phones

# ====================================================
# SIMPAN FILE
# ====================================================
def save_results(results, file_name):
    with open(file_name, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    logger.info(f"Hasil disimpan ke {file_name}")

# ====================================================
# MAIN PROGRAM
# ====================================================
async def main():
    print("\n===================================================")
    print("           TELEGRAM PHONE CHECKER V2 (AKURAT)")
    print("===================================================\n")

    file_input = input("Masukkan file nomor target: ").strip()
    target_numbers = read_phone_file(file_input)

    if not target_numbers:
        logger.error("File kosong atau tidak valid.")
        return

    login_numbers = input_login_numbers()

    if not login_numbers:
        logger.error("Tidak ada nomor login diberikan.")
        return

    # Loop setiap nomor login
    for phone_login in login_numbers:
        print(f"\n=== LOGIN: {phone_login} ===")

        session_path = os.path.join(
            SESSION_DIR, f"session_{phone_login.replace('+','')}"
        )

        client = TelegramClient(session_path, API_ID, API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            print(f"Mengirim kode OTP ke {phone_login}...")
            await client.send_code_request(phone_login)
            code = input(f"Masukkan kode OTP ({phone_login}): ").strip()

            try:
                await client.sign_in(phone=phone_login, code=code)
            except SessionPasswordNeededError:
                pwd = input("Masukkan password 2FA: ").strip()
                await client.sign_in(password=pwd)

        print("Login berhasil.\n")

        results = []
        print(f"Mengecek {len(target_numbers)} nomor...\n")

        # Cek semua nomor target
        for num in target_numbers:
            res = await check_phone_registered(client, num)
            results.append(res)

            # Tampilkan hasil ke console
            if res["status"] == "registered":
                print(f"✓ {num} TERDAFTAR - {res['first_name']}")
            elif res["status"] == "not_registered":
                print(f"✗ {num} TIDAK TERDAFTAR")
            else:
                print(f"⚠ ERROR {num}: {res['error']}")

            await asyncio.sleep(0.5)  # aman dari rate-limit

        # Simpan hasil dalam file
        output_file = f"results_{phone_login.replace('+','')}.json"
        save_results(results, output_file)

        await client.disconnect()

    print("\nSelesai! Semua hasil sudah disimpan.\n")

# ====================================================
# RUNNER
# ====================================================
if __name__ == "__main__":
    asyncio.run(main())
