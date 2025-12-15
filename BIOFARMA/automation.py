import re
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    CallbackQueryHandler, ContextTypes, filters
)

BOT_TOKEN = "7667684723:AAH06yQFvbnp47Jg1GnoiGJV8cfCS8Urcac"

# User state penyimpanan mode
USER_STATE = {}


# ----------------------------------------------------------
# Ekstraksi IP per baris
# ----------------------------------------------------------
def extract_ips_per_line(line):
    return re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)


# ----------------------------------------------------------
# Ekstrak Source IP = IP pertama per baris
# ----------------------------------------------------------
def extract_source_ips(text):
    lines = text.splitlines()
    result = []
    for line in lines:
        ips = extract_ips_per_line(line)
        if len(ips) >= 1:
            result.append(ips[0])
    return list(dict.fromkeys(result))


# ----------------------------------------------------------
# Ekstrak Destination IP = IP kedua per baris
# ----------------------------------------------------------
def extract_dest_ips(text):
    lines = text.splitlines()
    result = []
    for line in lines:
        ips = extract_ips_per_line(line)
        if len(ips) >= 2:
            result.append(ips[1])
    return list(dict.fromkeys(result))


# ----------------------------------------------------------
# /start → tampilkan tombol menu
# ----------------------------------------------------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("Check Source IP", callback_data="source")],
        [InlineKeyboardButton("Check Destination IP", callback_data="dest")],
    ]

    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        "Selamat datang!\nSilakan pilih jenis IP yang ingin diekstrak:",
        reply_markup=reply_markup
    )


# ----------------------------------------------------------
# Handler tombol menu
# ----------------------------------------------------------
async def button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    chat_id = query.message.chat_id

    if query.data == "source":
        USER_STATE[chat_id] = "WAIT_SOURCE"
        await query.edit_message_text(
            "Mode: Check Source IP\n\nSilakan kirim datanya (paste blok log Anda di sini)."
        )

    elif query.data == "dest":
        USER_STATE[chat_id] = "WAIT_DEST"
        await query.edit_message_text(
            "Mode: Check Destination IP\n\nSilakan kirim datanya (paste blok log Anda di sini)."
        )


# ----------------------------------------------------------
# Handler input data (setelah user pilih mode)
# ----------------------------------------------------------
async def process_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    text = update.message.text

    if chat_id not in USER_STATE:
        await update.message.reply_text("Silakan mulai dengan /start")
        return

    mode = USER_STATE[chat_id]

    if mode == "WAIT_SOURCE":
        ips = extract_source_ips(text)
        if ips:
            msg = "Source IP ditemukan:\n" + "\n".join(ips)
        else:
            msg = "Tidak ada Source IP yang ditemukan."
        await update.message.reply_text(msg)
        del USER_STATE[chat_id]

    elif mode == "WAIT_DEST":
        ips = extract_dest_ips(text)
        if ips:
            msg = "Destination IP ditemukan:\n" + "\n".join(ips)
        else:
            msg = "Tidak ada Destination IP yang ditemukan."
        await update.message.reply_text(msg)
        del USER_STATE[chat_id]


# ----------------------------------------------------------
# MAIN
# ----------------------------------------------------------
def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(button))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, process_text))

    print("BOT BERJALAN...")
    app.run_polling()


if __name__ == "__main__":
    main()
