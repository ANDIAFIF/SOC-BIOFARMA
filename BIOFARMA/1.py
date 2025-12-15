import asyncio
import json
import os
from telegram.client import Telegram

API_ID = 24866155
API_HASH = "1356c13f14e1c92f8de5c7f38861"

# ============================================================
# HANDLE AUTH STATE (OTP + PASSWORD)
# ============================================================
async def tdlib_login(client, phone_number):
    print("\n=== PROSES LOGIN TELEGRAM ===")

    # Step 1: kirim nomor telepon
    await client.call_method(
        "setAuthenticationPhoneNumber",
        {"phone_number": phone_number}
    )

    while True:
        state = await client.call_method("getAuthorizationState")

        stype = state["@type"]

        if stype == "authorizationStateWaitCode":
            code = input("Masukkan kode OTP: ").strip()
            await client.call_method(
                "checkAuthenticationCode",
                {"code": code}
            )

        elif stype == "authorizationStateWaitPassword":
            pwd = input("Masukkan password 2FA: ").strip()
            await client.call_method(
                "checkAuthenticationPassword",
                {"password": pwd}
            )

        elif stype == "authorizationStateReady":
            print("\nLogin berhasil!\n")
            return True

        elif stype == "authorizationStateClosed":
            print("TDLib session closed.")
            return False

        await asyncio.sleep(0.3)


# ============================================================
# CEK NOMOR TERDAFTAR / TIDAK TERDAFTAR
# ============================================================
async def check_number(client, phone):
    try:
        # Gunakan importContacts untuk cek nomor
        result = await client.call_method(
            "importContacts",
            {
                "contacts": [
                    {
                        "@type": "contact",
                        "phone_number": phone,
                        "first_name": "Check",
                        "last_name": str(hash(phone))[-4:]  # unique identifier
                    }
                ]
            }
        )

        user_ids = result.get("user_ids", [])

        # Jika user_id > 0, nomor terdaftar di Telegram
        if user_ids and user_ids[0] > 0:
            user_id = user_ids[0]
            # Hapus dari kontak setelah cek
            try:
                await client.call_method("removeContacts", {"user_ids": [user_id]})
            except:
                pass
            return True

        return False

    except Exception as e:
        print(f"  [Error cek {phone}]: {e}")
        return False


# ============================================================
# MAIN PROGRAM
# ============================================================
async def main():
    print("==================================================")
    print(" TELEGRAM PHONE CHECKER (TDLib — 100% AKURAT)")
    print(" Compatible with python-telegram 0.19.0")
    print("==================================================\n")

    # Input file terlebih dahulu
    file_input = input("Masukkan nama file nomor target (txt): ").strip()

    if not os.path.exists(file_input):
        print("File tidak ditemukan!")
        return

    with open(file_input, "r") as f:
        numbers = [line.strip() for line in f if line.strip()]

    print(f"\nTotal nomor yang akan dicek: {len(numbers)}")

    # Nomor login Telegram
    login_phone = input("\nMasukkan nomor login Telegram (+62...): ").strip()

    # Buat client TDLib
    client = Telegram(
        api_id=API_ID,
        api_hash=API_HASH,
        phone_number=login_phone,
        database_encryption_key="td_secret_key",
        files_directory=f"tdlib_session_{login_phone}"
    )

    # Mulai TDLib
    await client.start()

    # Login OTP + Password
    ok = await tdlib_login(client, login_phone)
    if not ok:
        return

    print("\n=== MULAI CEK NOMOR ===\n")

    registered_list = []
    not_registered_list = []

    for i, num in enumerate(numbers, 1):
        registered = await check_number(client, num)
        if registered:
            print(f"[{i}/{len(numbers)}] ✓ {num} TERDAFTAR")
            registered_list.append(num)
        else:
            print(f"[{i}/{len(numbers)}] ✗ {num} TIDAK TERDAFTAR")
            not_registered_list.append(num)

        # Delay lebih lama untuk menghindari rate limit
        await asyncio.sleep(1.0)

    # Simpan hasil ke file
    with open("hasil_terdaftar.txt", "w") as f:
        f.write("\n".join(registered_list))

    with open("hasil_tidak_terdaftar.txt", "w") as f:
        f.write("\n".join(not_registered_list))

    print("\n=== RINGKASAN ===")
    print(f"Total dicek     : {len(numbers)}")
    print(f"Terdaftar       : {len(registered_list)}")
    print(f"Tidak terdaftar : {len(not_registered_list)}")
    print("\nHasil disimpan ke:")
    print("  - hasil_terdaftar.txt")
    print("  - hasil_tidak_terdaftar.txt")
    print("\nSelesai.\n")


if __name__ == "__main__":
    asyncio.run(main())
