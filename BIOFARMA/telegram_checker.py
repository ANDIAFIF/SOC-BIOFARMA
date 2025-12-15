import asyncio
import os
from telethon import TelegramClient
from telethon.tl.functions.contacts import ImportContactsRequest, DeleteContactsRequest, ResolvePhoneRequest
from telethon.tl.types import InputPhoneContact
from telethon.errors import FloodWaitError, PhoneNotOccupiedError, PhoneNumberInvalidError, SessionPasswordNeededError

# ============================================================
# KONFIGURASI API
# ============================================================
API_ID = 16528366
API_HASH = "ca9dc45f1a383b6b084e48cf2f1f784c"

# ============================================================
# CEK NOMOR TELEGRAM (ResolvePhone + Fallback)
# ============================================================
async def check_phone_number(client, phone_number, index=0):
    """
    Cek apakah nomor terdaftar di Telegram.
    """
    phone_clean = phone_number.lstrip('+')

    try:
        # METODE UTAMA: ResolvePhoneRequest
        result = await client(ResolvePhoneRequest(phone=phone_clean))

        if result.users:
            user = result.users[0]
            return {
                "phone": phone_number,
                "registered": True,
                "user_id": user.id,
                "first_name": getattr(user, 'first_name', '') or "",
                "last_name": getattr(user, 'last_name', '') or "",
                "username": getattr(user, 'username', '') or "-",
                "is_bot": getattr(user, 'bot', False),
                "is_premium": getattr(user, 'premium', False),
            }

        return {"phone": phone_number, "registered": False}

    except PhoneNotOccupiedError:
        return {"phone": phone_number, "registered": False}

    except FloodWaitError as e:
        print(f"      ⚠ Rate limit! Tunggu {e.seconds} detik...")
        await asyncio.sleep(e.seconds + 1)
        return await check_phone_number(client, phone_number, index)

    except Exception as e:
        # Fallback ke ImportContacts
        try:
            contact = InputPhoneContact(
                client_id=index,
                phone=phone_number,
                first_name="Check",
                last_name=str(index)
            )
            result = await client(ImportContactsRequest([contact]))

            if result.users:
                user = result.users[0]
                user_info = {
                    "phone": phone_number,
                    "registered": True,
                    "user_id": user.id,
                    "first_name": user.first_name or "",
                    "last_name": user.last_name or "",
                    "username": user.username or "-",
                    "is_bot": user.bot,
                    "is_premium": getattr(user, 'premium', False),
                }
                try:
                    await client(DeleteContactsRequest([user.id]))
                except:
                    pass
                return user_info

            return {"phone": phone_number, "registered": False}

        except Exception as e2:
            return {"phone": phone_number, "registered": False, "error": str(e2)}


# ============================================================
# MAIN PROGRAM - MULTI AKUN ROTASI
# ============================================================
async def main():
    print("=" * 60)
    print(" TELEGRAM PHONE CHECKER - MULTI AKUN ROTASI")
    print(" Cek nomor dengan bergantian akun untuk hindari rate limit")
    print("=" * 60)

    # ==================== INPUT FILE ====================
    print("\n[1] INPUT FILE TARGET")
    file_input = input("    Nama file nomor (txt): ").strip()

    if not os.path.exists(file_input):
        print(f"    ✗ File '{file_input}' tidak ditemukan!")
        return

    with open(file_input, "r") as f:
        numbers = [line.strip() for line in f if line.strip()]

    if not numbers:
        print("    ✗ File kosong!")
        return

    print(f"    ✓ Total nomor target: {len(numbers)}")

    # ==================== INPUT JUMLAH AKUN ====================
    print("\n[2] SETUP MULTI AKUN")
    try:
        num_accounts = int(input("    Berapa akun yang ingin login? ").strip())
        if num_accounts < 1:
            num_accounts = 1
    except:
        num_accounts = 1

    print(f"    ✓ Akan login {num_accounts} akun")

    # ==================== LOGIN SEMUA AKUN ====================
    print("\n[3] LOGIN AKUN TELEGRAM")
    print("-" * 60)

    clients = []
    account_names = []

    for i in range(num_accounts):
        while True:  # Loop untuk retry jika error
            print(f"\n    === AKUN {i+1}/{num_accounts} ===")
            phone = input(f"    Masukkan nomor Telegram akun {i+1} (+62...): ").strip()

            # Validasi format nomor
            if not phone.startswith('+'):
                phone = '+' + phone

            if len(phone) < 10:
                print(f"    ✗ Nomor terlalu pendek! Coba lagi.")
                continue

            session_name = f"sessions/session_{phone.replace('+', '')}"
            client = TelegramClient(session_name, API_ID, API_HASH)

            try:
                print(f"    Connecting...")
                await client.start(phone=phone)

                me = await client.get_me()
                name = f"{me.first_name or ''} {me.last_name or ''}".strip()
                print(f"    ✓ Login berhasil: {name} (@{me.username or 'no username'})")

                clients.append(client)
                account_names.append(f"{name} ({phone})")
                break  # Keluar dari loop while, lanjut ke akun berikutnya

            except PhoneNumberInvalidError:
                print(f"    ✗ Nomor tidak valid! Pastikan format: +628xxxxxxxxxx")
                await client.disconnect()
                continue  # Retry input nomor

            except Exception as e:
                print(f"    ✗ Error: {e}")
                retry = input("    Coba lagi? (y/n): ").strip().lower()
                if retry != 'y':
                    await client.disconnect()
                    print("    Melewati akun ini...")
                    break
                await client.disconnect()

    print("\n" + "-" * 60)

    if not clients:
        print("✗ Tidak ada akun yang berhasil login! Keluar.")
        return

    print(f"✓ Total {len(clients)} akun berhasil login:")
    for i, name in enumerate(account_names):
        print(f"    [{i+1}] {name}")

    # ==================== MULAI CEK DENGAN ROTASI ====================
    print("\n[4] MULAI CEK NOMOR (ROTASI AKUN)")
    print("-" * 60)

    registered_list = []
    not_registered_list = []

    total_numbers = len(numbers)
    total_accounts = len(clients)

    for i, phone in enumerate(numbers):
        # Pilih akun berdasarkan rotasi (0, 1, 2, 0, 1, 2, ...)
        account_index = i % total_accounts
        client = clients[account_index]
        account_name = account_names[account_index]

        # Cek nomor
        result = await check_phone_number(client, phone, i)

        if result.get("registered"):
            name = f"{result['first_name']} {result['last_name']}".strip()
            username = result['username']
            premium = "⭐" if result.get('is_premium') else ""

            print(f"[{i+1:03}/{total_numbers}] ✓ {phone}")
            print(f"            Nama: {name} {premium}")
            print(f"            Username: @{username}")
            print(f"            [via Akun {account_index+1}]")

            registered_list.append({
                "phone": phone,
                "name": name,
                "username": username,
                "user_id": result['user_id'],
                "premium": result.get('is_premium', False),
                "checked_by": account_name
            })
        else:
            print(f"[{i+1:03}/{total_numbers}] ✗ {phone} - TIDAK TERDAFTAR [via Akun {account_index+1}]")
            not_registered_list.append(phone)

        # Delay kecil antar request
        await asyncio.sleep(0.5)

    print("-" * 60)

    # ==================== SIMPAN HASIL ====================
    print("\n[5] MENYIMPAN HASIL")

    # File terdaftar (detail)
    with open("hasil_terdaftar.txt", "w") as f:
        f.write("NOMOR TERDAFTAR DI TELEGRAM\n")
        f.write("=" * 50 + "\n\n")
        for item in registered_list:
            f.write(f"Phone    : {item['phone']}\n")
            f.write(f"Nama     : {item['name']}\n")
            f.write(f"Username : @{item['username']}\n")
            f.write(f"User ID  : {item['user_id']}\n")
            f.write(f"Premium  : {'Ya' if item['premium'] else 'Tidak'}\n")
            f.write(f"Dicek via: {item['checked_by']}\n")
            f.write("-" * 30 + "\n")

    # File tidak terdaftar
    with open("hasil_tidak_terdaftar.txt", "w") as f:
        f.write("\n".join(not_registered_list))

    # File CSV
    with open("hasil_telegram.csv", "w") as f:
        f.write("phone,name,username,user_id,premium,registered,checked_by\n")
        for item in registered_list:
            name_clean = item['name'].replace(',', ' ')
            checked_clean = item['checked_by'].replace(',', ' ')
            f.write(f"{item['phone']},{name_clean},@{item['username']},{item['user_id']},{item['premium']},true,{checked_clean}\n")
        for phone in not_registered_list:
            f.write(f"{phone},-,-,-,false,false,-\n")

    # ==================== RINGKASAN ====================
    print("\n" + "=" * 60)
    print(" RINGKASAN HASIL")
    print("=" * 60)
    print(f"  Total akun digunakan : {total_accounts}")
    print(f"  Total nomor dicek    : {total_numbers}")
    print(f"  Terdaftar            : {len(registered_list)}")
    print(f"  Tidak terdaftar      : {len(not_registered_list)}")
    print(f"\n  File output:")
    print(f"    - hasil_terdaftar.txt")
    print(f"    - hasil_tidak_terdaftar.txt")
    print(f"    - hasil_telegram.csv")
    print("=" * 60)

    # ==================== DISCONNECT SEMUA ====================
    print("\n[6] MENUTUP KONEKSI...")
    for client in clients:
        await client.disconnect()

    print("✓ Selesai!\n")


if __name__ == "__main__":
    asyncio.run(main())
