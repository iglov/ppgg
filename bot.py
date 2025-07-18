#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=unused-argument

import os
import hashlib
import logging
from datetime import datetime
from io import BytesIO
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
from PIL import Image
import magic

# === Setup logging ===
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# === Load environment variables ===
logger.debug("Loading environment variables...")
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
IMAGE_DIR = os.getenv("IMAGE_DIR", "/var/www/images")
ALLOWED_MASTERS = set(map(int, os.getenv("ALLOWED_MASTERS", "").split(",")))

logger.info(f"Allowed master IDs: {ALLOWED_MASTERS}")
logger.info(f"Image storage directory: {IMAGE_DIR}")

# === MD5 calculation ===
def calculate_md5(data: bytes) -> str:
    logger.debug("Calculating MD5 hash of image data.")
    md5_hash = hashlib.md5()
    md5_hash.update(data)
    result = md5_hash.hexdigest()
    logger.debug(f"MD5 hash calculated: {result}")
    return result

# === /upload command handler ===
async def upload_image(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.info("Received /upload command.")

    message = update.message
    user = update.effective_user

    # Check if user is allowed
    if user.id not in ALLOWED_MASTERS:
        logger.warning(f"User {user.id} is not in allowed masters list.")
        await message.reply_text("You are not allowed to upload images.")
        return

    # Determine which message to use
    replied_msg = message.reply_to_message
    if replied_msg:
        logger.debug("Using replied message.")
        source_message = replied_msg
    elif message.photo:
        logger.debug("No reply, using message's own photo.")
        source_message = message
    else:
        logger.warning("Command not used on a photo or reply to a photo.")
        await message.reply_text("Ты ебанутый чи да? Используй /upload цитируя месседж с картинкой, наркоман!")
        return

    if not source_message.photo:
        logger.warning("Target message does not contain a photo.")
        await message.reply_text("Че это за хуйня? Картинку, блять, нормальную приложи!")
        return

    logger.info("Downloading image file from Telegram server...")
    photo = source_message.photo[-1]  # Get the largest image
    photo_file = await photo.get_file()
    file_data = await photo_file.download_as_bytearray()
    logger.info(f"Downloaded image of size {len(file_data)} bytes.")

    # Convert bytearray to bytes for python-magic compatibility
    file_bytes = bytes(file_data)
    logger.debug(f"Image converted from bytearray to bytes (size: {len(file_bytes)}).")

    # Detect MIME type
    logger.debug("Detecting MIME type of the image.")
    mime = magic.Magic(mime=True)
    mime_type = mime.from_buffer(file_bytes)
    logger.info(f"Detected MIME type: {mime_type}")

    if not mime_type.startswith('image/'):
        logger.warning(f"Unsupported file type: {mime_type}")
        await message.reply_text("Ой иди нахуй хакер комнатный!")
        return

    # Convert to WebP first
    logger.info("Converting image to WebP format.")
    try:
        image = Image.open(BytesIO(file_bytes))
        webp_image_io = BytesIO()
        image.save(webp_image_io, format='WEBP', lossless=True)  # lossless=True for lossless compression
        webp_data = webp_image_io.getvalue()
        logger.info(f"Image successfully converted to WebP (size: {len(webp_data)} bytes).")
    except Exception as e:
        logger.error(f"Image conversion error: {e}", exc_info=True)
        await message.reply_text("бип-боп, я робот долбайоп: не получилось законвертить!")
        return

    # Calculate MD5 of the converted image
    logger.debug("Calculating MD5 hash of the converted WebP image.")
    md5_hash = calculate_md5(webp_data)

    # Check for existing image by MD5
    logger.debug(f"Checking for existing image with MD5: {md5_hash}")
    duplicate_found = False
    try:
        for filename in os.listdir(IMAGE_DIR):
            if filename.endswith('.webp'):
                file_path = os.path.join(IMAGE_DIR, filename)
                logger.debug(f"Comparing with existing file: {file_path}")
                with open(file_path, 'rb') as f:
                    existing_data = f.read()
                    existing_md5 = calculate_md5(existing_data)
                    if existing_md5 == md5_hash:
                        logger.info(f"Duplicate image found: {filename}")
                        duplicate_found = True
                        break
    except Exception as e:
        logger.error(f"Error checking existing files: {e}", exc_info=True)
        await message.reply_text("бип-боп, я робот долбайоп: не получилось вычислить md5!")
        return

    if duplicate_found:
        logger.info("Image already exists on server.")
        await message.reply_text("Ты долбаеб чи да? Есть уже такое, глаза протри!")
        return

    # Generate filename based on message date
    msg_date: datetime = source_message.date
    filename = msg_date.strftime('%Y%m%d%H%M') + '.webp'
    file_path = os.path.join(IMAGE_DIR, filename)
    logger.info(f"Generated filename: {filename}")

    # Save the file
    logger.info(f"Saving image to {file_path}...")
    try:
        with open(file_path, 'wb') as f:
            f.write(webp_data)
        logger.info(f"Image saved successfully to {file_path}")
        await message.reply_text(f"Я воль хер майор! Успешно закоммитил в зал славы: {filename}")
    except Exception as e:
        logger.error(f"Error saving file: {e}", exc_info=True)
        await message.reply_text("бип-боп, я робот долбайоп: не получилось схоронить :(")

# === Main function to run the bot ===
def main():
    logger.info("Starting bot application...")
    app = ApplicationBuilder().token(TOKEN).build()
    logger.info("Bot application initialized.")

    logger.debug("Adding command handler for /upload")
    app.add_handler(CommandHandler("upload", upload_image))

    logger.info("Starting polling...")
    app.run_polling()

if __name__ == '__main__':
    main()
