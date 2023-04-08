import telebot
from telebot import types
from Crypto.Cipher import ChaCha20
from Crypto.Util.Padding import pad, unpad
import os

key = os.urandom(32)
nonce = os.urandom(8)
Api_Key = "6128069220:AAGwBaVvB6lZO21ha6wnFCdvHpI8UhzlcIU"
bot = telebot.TeleBot(Api_Key)


def encrypt_chacha20(plaintext):
  cipher = ChaCha20.new(key=key, nonce=nonce)
  ciphertext = cipher.encrypt(pad(plaintext.encode(), ChaCha20.block_size))
  return ciphertext, nonce


def decrypt_chacha20(ciphertext, nonce):
  cipher = ChaCha20.new(key=key, nonce=nonce)
  plaintext = unpad(cipher.decrypt(ciphertext), ChaCha20.block_size).decode()
  return plaintext


@bot.message_handler(commands=['start'])
def greet(message):
  bot.send_photo(
    message.chat.id,
    "https://ibb.co/P6PKGWV",
    caption=
    f"<b>Welcome To Encryption 🔐 Ai Bot .</b> \n \nThis Bot is used for encrypting a contract address into a format which snipers, telegram scrappers cant detect so the launch is without bots.\n\n<i>use /encrypt then contract address to encrypt the contract \nuse /decrypt to get the contract address from encrypted message</i>\n\n",
    parse_mode="html")


@bot.message_handler(commands=['encrypt'])
def encrypt(message):
  plaintext = message.text.split(' ')[1]
  if plaintext.startswith("0x"):
    ciphertext, nonce = encrypt_chacha20(plaintext)
    bot.send_message(
      message.chat.id,
      f"<i>Below is the encrypted message for the contract address you sent.Click to copy the encrypted message use /decrypt to get back the contract address</i>\n\n<pre>{ciphertext.hex()},{nonce.hex()}</pre>",
      parse_mode="html")
  else:
    bot.send_message(
      message.chat.id,
      f"<b>This is not a contract address. Try again with a valid address</b>",
      parse_mode="html")


@bot.message_handler(commands=['decrypt'])
def decrypt(message):
  parts = message.text.split(' ')[1].split(',')
  if len(parts) != 2:
    bot.send_message(
      message.chat.id,
      f"<b>Invalid input format. Please provide the ciphertext and nonce separated by a comma.</b>",
      parse_mode="html")
  else:
    try:
      ciphertext = bytes.fromhex(parts[0])
      nonce = bytes.fromhex(parts[1])
      plaintext = decrypt_chacha20(ciphertext, nonce)
      maestro = types.InlineKeyboardButton(
        "Buy Using Maestro",
        url=f"https://t.me/MaestroSniperBot?start={plaintext}")
      reply_markup = types.InlineKeyboardMarkup([[maestro]])
      bot.send_message(message.chat.id,
                       f"<pre>{plaintext}</pre>",
                       parse_mode="html",
                       reply_markup=reply_markup)
    except ValueError:
      bot.send_message(message.chat.id,
                       f"<b>Invalid ciphertext or nonce.</b>",
                       parse_mode="html")


bot.polling()
