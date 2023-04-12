import telebot
import requests
import json
from telebot import types
from web3 import Web3
from moralis import evm_api
import datetime
import pickle
from mnemonic import Mnemonic
from abi import abiLp
from abi import abiTeam
from abi import abiUni

import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

key = os.urandom(32)
iv = os.urandom(16)

mainData = {}
infura = "https://mainnet.infura.io/v3/c1f653384020470d942fdd4d8eb97795"
w3 = Web3(Web3.HTTPProvider(infura))
w4 = Web3(
  Web3.HTTPProvider(
    "https://shy-white-knowledge.discover.quiknode.pro/3dd1414d33024c972650675c3437e2a23c8db00f/"
  ))
moralis_key = "GFe9A3lNYWFSv1jO5NmC14bUHeW4oedryp1BPUHxAnAMZUL7C3Nd0Ppjaru3003R"
Api_Key = "5176832558:AAG-q5T9wjzeasPTzrFBVLcQPyafx4T3oWE"
#Api_Key = "6031453420:AAHu_1ikCgFYMId_wz-LWuoDMgjiRHuQpdQ"
bot = telebot.TeleBot(Api_Key)
freeKey = "EK-cgMkq-f79VYYW-u1JY5"
ourTokenCa = "0x0a7c0E94abF1948c3c577527f9448FD344a848b0"
#verifiedAddy = []
#allowedCache = [
# 795341146, 690109921, 5052062408, 869973778, 1001550693632, 917731336
#]
addy_cache = 'addy.pickle'
file_name = 'cached_array.pickle'
ethApi = "7UMIKS3MQXWYW975VTPF84Y25EDW4B2NXA"
apikeyeth = "7UMIKS3MQXWYW975VTPF84Y25EDW4B2NXA"
alphaHit = 0
checkedCa = {}
checkedCa_cache = 'checkedCa.pickle'


def cache_data(data, file_name):
  with open(file_name, 'wb') as f:
    pickle.dump(data, f)


def load_cached_data(file_name):
  try:
    with open(file_name, 'rb') as f:
      return pickle.load(f)
  except FileNotFoundError:
    return None


#cache_data(allowedCache, file_name)
#cache_data(verifiedAddy, addy_cache)
#cache_data(checkedCa, checkedCa_cache)
verifiedAddyCache = load_cached_data(addy_cache)
allowed = load_cached_data(file_name)
#print(allowed)
#allowed.push(-)
checkedCa = load_cached_data(checkedCa_cache)
#print(verifiedAddyCache)


def encrypt_AES(plaintext):
  cipher = AES.new(key, AES.MODE_CBC, iv)
  padded_plaintext = pad(plaintext.encode(), AES.block_size)
  ciphertext = cipher.encrypt(padded_plaintext)
  return ciphertext


def decrypt_AES(ciphertext):
  cipher = AES.new(key, AES.MODE_CBC, iv)
  padded_plaintext = cipher.decrypt(ciphertext)
  plaintext = unpad(padded_plaintext, AES.block_size).decode()
  return plaintext


@bot.message_handler(commands=['encrypt'])
def encrypt(message):
  plaintext = message.text.split(' ')[1]
  ciphertext = encrypt_AES(plaintext)
  bot.send_message(message.chat.id,
                   f"Encrypted message: <pre>{ciphertext.hex()}</pre>",
                   parse_mode="html")


@bot.message_handler(commands=['decrypt'])
def decrypt(message):
  ciphertext = bytes.fromhex(message.text.split(' ')[1])
  plaintext = decrypt_AES(ciphertext)
  bot.send_message(message.chat.id,
                   f"Decrypted message: <pre>{plaintext}</pre>",
                   parse_mode="html")


@bot.message_handler(commands=["snipers"])
def snipers(message):
  snipes = 0
  ca = message.text.split(" ")[1].lower()
  if ca.startswith("0x"):
    mempool_txns = w4.eth.get_block('pending').transactions
    for txn in mempool_txns:
      try:
        hash = txn.hex()
        txn = w3.eth.get_transaction(hash)
        to_address = txn['to'].lower()
        if ca == to_address:
          snipes = snipes + 1
      except:
        print("k")
    bot.send_message(
      message.chat.id,
      f"<b>Number of people trying to buy the contract</b>\n\n<pre>{ca}</pre>:- {snipes}",
      parse_mode="html")


@bot.message_handler(commands=["allow"])
def allow(message):
  id = int(message.text.split(" ")[1])
  if id in allowed:
    bot.send_message(message.chat.id, f"User Is Already verified")
  else:
    allowed.append(id)
    cache_data(allowed, file_name)


@bot.message_handler(commands=["remove"])
def remove(message):
  try:
    id = int(message.text.split(" ")[1])
    allowed.remove(id)
    cache_data(allowed, file_name)
  except:
    bot.send_message(message.chat.id, f"Incorrect UserId")


@bot.message_handler(commands=["maja"])
def maja(message):
  factory_address = '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f'
  factory = w3.eth.contract(address=factory_address, abi=abiUni)
  latest_block_number = w3.eth.blockNumber
  events = factory.events.PairCreated().getLogs(fromBlock=latest_block_number -
                                                1000,
                                                toBlock=latest_block_number)
  last_5_events = events[-1:-10:-1]
  for event in last_5_events:
    a = event.transactionHash.hex()
    api_key = "GFe9A3lNYWFSv1jO5NmC14bUHeW4oedryp1BPUHxAnAMZUL7C3Nd0Ppjaru3003R"
    params = {
      "transaction_hash": a,
      "chain": "eth",
    }

    result = evm_api.transaction.get_transaction(
      api_key=api_key,
      params=params,
    )

    hex = result['input'][:5]
    #print(event['args'])
    token = (event['args']['token0'])
    #token1 = (event['args']['token0'])
    eth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".lower()
    print(hex)
    if hex.startswith("0x6"):
      if token.lower() != eth:
        larp(message, token)
        print("jdnjj")
      else:
        print("jfvnn")
    else:
      if token.lower() != eth:
        get_contract_holders(message, token)
      else:
        print("djjnj")


@bot.message_handler(commands=["bsc"])
def bsc(message):
  cooldown = 0
  emojiRed = "🔴"
  emojiGreen = "🟢"
  if message.text.split(" ")[1].startswith("0x"):
    ca = message.text.split(" ")[1]
    ca = w3.toChecksumAddress(ca)
    #chain_id = 56
    url = f"https://api.gopluslabs.io/api/v1/token_security/56?contract_addresses={ca}"
    res = requests.get(url)
    data = res.text
    realD = json.loads(data)
    value = realD["result"][ca.lower()]
    print(value)
    name = value['token_name']
    symbol = value['token_symbol']
    supply = value['total_supply']
    if 'trading_cooldown' in value:
      cooldown = int(value['trading_cooldown'])

    if cooldown == 0:
      cooldown = "False"
    else:
      cooldown = "True"
    tradingPause = int(value['transfer_pausable'])
    if tradingPause == 0:
      tradingPause = "False"
    else:
      tradingPause = "True"
    slippageModify = int(value['slippage_modifiable'])
    if slippageModify == 0:
      slippageModify = "True"
    else:
      slippageModify = "Yes"
    ownerAddress = value['owner_address']
    ownerPercentage = value['owner_percent']
    previousHoney = int(value['honeypot_with_same_creator'])
    if previousHoney == 0:
      previousHoney = "The deployer wallet is not linked to any previous rugs"
    else:
      previousHoney = "Deployer wallet seems to be linked with some rug❌"

    antiWhale = value['is_anti_whale']
    blacklistFn = int(value['is_blacklisted'])
    if blacklistFn == 0:
      blacklistFn = "False"
    else:
      blacklistFn = "True"
    whitelistFn = int(value['is_whitelisted'])
    if whitelistFn == 0:
      whitelistFn = "False"
    else:
      whitelistFn = "True"

    honeypot = int(value['is_honeypot'])
    if honeypot == 0:
      honeypot = "Dosent Seem Like A Honeypot 🟢✅"
    else:
      honeypot = "Might Be A Honeypot 🔴🔴"
    mint = int(value['is_mintable'])
    if mint == 0:
      mint = "False"
    else:
      mint = "True"
    hiddenOwner = int(value['hidden_owner'])
    if hiddenOwner == 0:
      hiddenOwner = "False"
    else:
      hiddenOwner = "True"
    holders = value['holder_count']
    liqudity = round(float(value['dex'][0]['liquidity']))
    deployer = value['creator_address']
    deployer = f"<a href='bscscan.com/address/{deployer}'>{deployer}</a>"
    deployerPercentage = round(float(value['creator_percent']) * 100, 2)
    cannotBuy = int(value['cannot_buy'])
    if cannotBuy == 0:
      cannotBuy = "True"
    else:
      cannotBuy = "False"
    cannotSell = int(value['cannot_sell_all'])
    if cannotSell == 0:
      cannotSell = "True"
    else:
      cannotSell = "False"
    takebackOwnership = int(value['can_take_back_ownership'])
    if takebackOwnership == 0:
      takebackOwnership = "False"
    else:
      takebackOwnership = "True"
    buyTax = round(float(value['buy_tax']) * 100, 1)
    sellTax = round(float(value['sell_tax']) * 100, 1)
    maxTxModifiable = value['anti_whale_modifiable']
    keyboard = [[
      types.InlineKeyboardButton("Poocoin",
                                 url=f"https://poocoin.app/tokens/{ca}"),
      types.InlineKeyboardButton("DexScreener",
                                 url=f"https://dexscreener.com/bsc/{ca}")
    ],
                [
                  types.InlineKeyboardButton(
                    "Honeypot Checker",
                    url=f"https://honeypot.is/bsc?address={ca}"),
                  types.InlineKeyboardButton(
                    "Buy Using Maestro",
                    url=f"https://t.me/MaestroSniperBot?start={ca}")
                ]]
    reply_markup = types.InlineKeyboardMarkup(keyboard)

    bot.send_message(
      message.chat.id,
      f"<b>{honeypot}</b>\n\n<b>Name:-</b> <i>{name}</i>\n<b>Symbol:-</b> <i>{symbol}</i>\n<b>Total Supply:-</b><i>{supply}</i>\n<b>Holders :-</b> <i>{holders}</i>\n<b>Contract:- </b><pre><i>{ca}</i></pre>\n<b>Tax:- </b> <i>{buyTax}/{sellTax}</i>\n<b>Liquidity:-</b> <i> {liqudity}$</i>\n\n<b>Important Functions In Contract</b>\n\n<b>Can Sell</b> :-<i> {cannotSell}</i>\n<b>Can Take Back Ownership</b> :- <i>{takebackOwnership}</i>\n<b>Blacklist Function In Contract </b>:- <i> {blacklistFn}</i>\n<b>WhiteList Function In Contract </b>:- <i> {whitelistFn}</i>\n<b>Owner Can Mint Tokens </b>:- <i>{mint}</i>\n<b>Owner Can Pause Trading</b> :-<i> {tradingPause}</i>\n<b>Contract Has Trading CoolDown</b>:- <i>{cooldown}</i>\n\n<b>Deployer Wallet Information</b>\n\n<b>Deployer:- </b>{deployer}\n\n<i>Deployer Wallet holds {deployerPercentage}% of supply\n\n{previousHoney}</i>",
      parse_mode="html",
      disable_web_page_preview=True,
      reply_markup=reply_markup)


@bot.message_handler(commands=["verify"])
def verify(message):
  if message.chat.id in allowed:
    bot.send_animation(
      message.chat.id,
      animation="https://media.giphy.com/media/Y07F3fs9Is5byj4zK8/giphy.gif",
      caption=f"<b>You're Already Verified :) </b>",
      parse_mode="html")
  else:
    mnemo = Mnemonic("english")
    words = mnemo.generate(strength=256)
    seed = mnemo.to_seed(words, passphrase="")
    account = w3.eth.account.privateKeyToAccount(seed[:32])
    private_key = account.privateKey
    public_key = account.address
    private_key = private_key.hex()
    #public_key = int(public_key)
    bot.send_message(message.chat.id,
                     f"<b><i>{public_key}</i></b>",
                     parse_mode="html")
    bot.send_message(
      message.chat.id,
      f"<b><i>To Get Verified And Access To The bot Make Sure You Have more than .5% of supply.\n\nIf you have then copy the above wallet address and send 1 token to that address. \n\nThen reply to this message with your transaction hash </i></b> ",
      parse_mode="html",
    )
    bot.register_next_step_handler(message,
                                   process_name_step,
                                   data={'publicKey': public_key})


def process_name_step(message, data):
  hash = message.text
  public_key = data["publicKey"]
  if hash.startswith("0x"):
    #print("hi", hash)
    checkTxHash(hash, message, public_key)
  if hash.startswith("http"):
    #print("hlo", hash)
    newTx = hash.split("/")[4]
    checkTxHash(newTx, message, public_key)
  else:
    bot.send_message(
      message.chat.id,
      f"<b><i>The tx hash you sent is incorrect try again !! </i></b>",
      parse_mode="html")


def checkTxHash(tx, message, public_key):
  global allowed
  global ourTokenCa
  global verifiedAddyCache
  print(allowed, message.chat.id)
  freeKey2 = "EK-8RsfJ-ckCnNW5-ddbmS"
  url = f"https://api.ethplorer.io/getTxInfo/{tx}?apiKey={freeKey2}"
  res = requests.get(url)
  data = res.text
  realD = json.loads(data)
  op = realD['operations']
  fromAddy = op[0]['from']
  toAddy = op[0]['to']
  value = op[0]['value']
  decimal = op[0]['tokenInfo']['decimals']
  addressca = op[0]['tokenInfo']['address']
  addressca = addressca.lower()
  ourTokenCa = ourTokenCa.lower()
  toAddy = toAddy.lower()
  public_key = public_key.lower()
  #addressca = addressca.encode('utf-8')
  #ourTokenCa = ourTokenCa.encode('utf-8')
  realValue = int(value) / 10**int(decimal)
  realValue = int(realValue)
  #print(addressca)
  #print("-------------------")
  #print(ourTokenCa)
  #if realValue > 1 and addressca == ourTokenCa and toAddy == public_key and fromAddy not in verifiedAddyCache:
  if realValue > 1:
    urlCheck = ("https://api.etherscan.io/api?"
                "module=account"
                "&action=tokenbalance"
                f"&contractaddress={ourTokenCa}"
                f"&address={fromAddy}"
                "&page=1"
                "&offset=100"
                "&startblock=0"
                "&endblock=27025780"
                "&sort=asc"
                "&apikey=H2IA5SV98N5KVTCIDE65KI3EECYRHNUYNF")
    response = requests.get(urlCheck)
    datac = response.text
    balance = json.loads(datac)['result']
    balanceint = int(balance) / 10**int(decimal)
    if balanceint > 100000:
      print(allowed)
      id = int(message.chat.id)
      bot.send_animation(
        message.chat.id,
        animation="https://media.giphy.com/media/Y07F3fs9Is5byj4zK8/giphy.gif",
        caption=f"<b>Yayy!! Congrats You're  Verified :) </b>",
        parse_mode="html")
      allowed.append(id)
      verifiedAddyCache.append(fromAddy)
      bot_id = 795341146
      print(bot_id)
      bot.send_message(bot_id,
                       f"User Verified {message.chat.id},\nAddy = {fromAddy}")
      cache_data(allowed, file_name)
      cache_data(verifiedAddyCache, addy_cache)

    else:
      bot.send_message(
        message.chat.id,
        "<b>You dont have sufficent Tokens</b><i>Buy Now MF</i>",
        parse_mode="html")
  else:
    bot.send_message(message.chat.id,
                     "<b>You're TX Dosent match try again</b>",
                     parse_mode="html")


@bot.message_handler(commands=["help"])
def help(message):
  bot.send_message(
    message.chat.id,
    f"<b><i>Hey Before You Use The Bot Make Sure You Have .5 supply of Smart Wallet AI Token And then Dm @WenCGWenCMC With Your User id <span class = 'tg-spoiler'><u>{message.chat.id}</u></span></i></b>",
    parse_mode="html")


@bot.message_handler(commands=["info"])
def getInfo(message):
  if message.chat.id not in allowed:
    bot.send_message(message.chat.id, "Access Denied.")
    return
  print(message.text)
  user_name = message.from_user.first_name
  if not message.text.split(" ")[1].startswith("0x"):
    bot.send_message(
      message.chat.id,
      f"<tg-spoiler><b><i>Hey {user_name}, I Know you have nothing to do in life apart from shitcoins but i have a life pls send correct ca</i></b></tg-spoiler>",
      parse_mode="html")

  else:
    caInfo = message.text.split(" ")[1]
    mainSabkaBaap(message, caInfo)


def mainSabkaBaap(message, caInfo):
  emojiTick = '\U00002714'
  emojiCross = '\U0000274C'
  try:

    dexurl = f"https://api.dexscreener.com/latest/dex/tokens/{caInfo}"
    ress = requests.get(dexurl)
    deta = ress.text
    realRes = json.loads(deta)
    #print(realRes['pairs'][0])
    liqudity = realRes['pairs'][0]['liquidity']['usd']
    liqudity = float(liqudity)
    pooledEth = realRes['pairs'][0]['liquidity']['quote']
    pooledEth = round(pooledEth, 2)

    url = f"https://api.ethplorer.io/getTokenInfo/{caInfo}?apiKey={freeKey}"
    response_API = requests.get(url)
    data = response_API.text
    realData = json.loads(data)
    #print(realData)
    name = realData["name"]
    holderCount = realData["holdersCount"]
    symbol = realData["symbol"]
    tax = getTaxes(caInfo)
    if isinstance(tax, str):
      textTax = tax
    elif tax[0] == False or tax[1] == False:
      textTax = ""
    else:
      textTax = f"Buy Tax {tax[0]} | Sell Tax {tax[1]}"
    deployer = realData["owner"]
    if deployer.startswith("0x0000"):
      renounce = f"Contract Is Renounced {emojiTick}"
    else:
      renounce = f"Contract is not Renounced {emojiCross}"
    totalSupply = realData["totalSupply"]
    decimal = realData['decimals']
    decimals = 10**float(decimal)
    realSupply = float(totalSupply) / float(decimals)
    realSupply = int(realSupply)
    #print(float(totalSupply) / decimal)
    txs = realData["transfersCount"]
    url2 = f"https://api.ethplorer.io/getTopTokenHolders/{caInfo}?apiKey={freeKey}&limit=50"
    response_API2 = requests.get(url2)
    data2 = response_API2.text
    real_data2 = json.loads(data2)
    share2 = get_holders(real_data2["holders"], "share")
    if len(share2) == 1:
      topBuyer = share2[0]
    else:
      share2.pop(0)
      topBuyer = share2[0]
    price = realRes['pairs'][0]['priceUsd']
    mcap = float(price) * realSupply
    mcap = round(mcap, 1)

    deployerReal = checkDeployer(caInfo)
    avg = 0
    for i, shr in enumerate(share2):
      avg = avg + shr

    avg = avg / len(share2)
    avg = round(avg, 2)
    ratio = round(mcap / liqudity, 2)
    deployerLinks = f"<a href='https://etherscan.io/address/{deployerReal}'>Deployer Wallet</a>"
    contractCheckKrlo = f"<a href='https://etherscan.io/token/{caInfo}'>Contract</a>"
    keyboard = [[
      types.InlineKeyboardButton(
        "Dextools",
        url=f"https://www.dextools.io/app/en/ether/pair-explorer/{caInfo}"),
      types.InlineKeyboardButton(
        "DexScreener", url=f"https://dexscreener.com/ethereum/{caInfo}")
    ],
                [
                  types.InlineKeyboardButton(
                    "Honeypot Checker",
                    url=f"https://honeypot.is/ethereum?address={caInfo}"),
                  types.InlineKeyboardButton(
                    "Buy Using Maestro",
                    url=f"https://t.me/MaestroSniperBot?start={caInfo}")
                ]]
    reply_markup = types.InlineKeyboardMarkup(keyboard)
    check = check_contract(deployerReal, caInfo)
    time = check[2]
    funder = f"<a href='https://etherscan.io/address/{check[1]}'>Funded By</a>"
    if check[0] == 1:
      word = f"Deployer wallet has no past projects{emojiCross}"
    else:
      word = f"Deployer has {(check[0]-1)} past projects{emojiTick}"


#print(word)
    bot.send_message(
      message.chat.id,
      f"<strong><b>Basic Info</b></strong>\n------------------\n<i>{name} ({symbol}) ETH\n{textTax}\n<b>Total Supply</b>:- {realSupply}\n<b>Decimals</b>:- {int(decimal)}\n<b>Launched</b>:- {time}\n<b>MarketCap</b>:-  ${mcap}\n<b>Liquidity</b>:- {pooledEth}eth\n<b>Mc/Liq</b>:- {ratio}\n<b>Total Transcations</b>:- {txs}\n<b>Holders</b>:- {holderCount} </i>\n\n<b>Some Important Details</b>\n---------------------------------------\n<i>{renounce}\nTop Holder Has {topBuyer}% of supply\nAverage wallet distribution of first 50 wallets is {avg}%\n{word}</i>\n\n{deployerLinks} | {contractCheckKrlo} | {funder}\n\n<b>Always Do Your Own Reasearch Bot Only Provide You tools to filter out projects but it does not guarrente the project is safe.</b>",
      parse_mode="html",
      reply_markup=reply_markup,
      disable_web_page_preview=True)
  except:
    bot.send_message(
      message.chat.id,
      f"<b>Some Error Ocuured Most Likely Caused If Token is not live yet</b>",
      parse_mode="html")


def checkDeployer(caInfo):
  url = f"https://api.etherscan.io/api?module=account&action=txlist&address={caInfo}&startblock=0&endblock=99999999&sort=asc&apiKey=7UMIKS3MQXWYW975VTPF84Y25EDW4B2NXA"
  response = requests.get(url)
  data = response.json()
  #print(data)
  deployer = (data['result'][0]['from'])
  return deployer


def check_contract(deployer, caInfo):
  #print(infoToken)
  url = f"https://api.etherscan.io/api?module=account&action=txlist&address={deployer}&startblock=0&endblock=99999999&sort=asc&apikey=7UMIKS3MQXWYW975VTPF84Y25EDW4B2NXA"
  response = requests.get(url)
  data = response.json()
  transactions = data['result']
  #transactions = transactions[::-1]
  funder = transactions[0]["from"]
  contract_count = 0
  for transaction in transactions:
    if transaction['contractAddress'] != "":
      contract_count += 1

    if transaction['contractAddress'].lower() == caInfo.lower():
      #print("hii")

      uni = transaction['timeStamp']
      uni = float(uni)
      current_time = datetime.datetime.now().timestamp()

      time_difference = current_time - uni
      dt = datetime.timedelta(seconds=time_difference)
      days = dt.days
      hours, remainder = divmod(dt.seconds, 3600)
      minutes, seconds = divmod(remainder, 60)
      if days == 1:
        time_difference_str = f"1 day"
      elif days == 0:
        time_difference_str = f""
      else:
        time_difference_str = f"{days} days"

      if hours == 1:
        time_difference_str += f" 1 hr"
      elif hours == 0:
        time_difference_str += f""
      else:
        time_difference_str += f" {hours} hrs"

      if minutes == 1:
        time_difference_str += f" 1 min"
      else:
        time_difference_str += f" {minutes} mins"

      if seconds == 1:
        time_difference_str += f" 1 sec"
      else:
        time_difference_str += f" {seconds} secs"
      #print(time_difference_str)

  return [contract_count, funder, time_difference_str]


def greetings(addy, message, msg):
  if len(addy) >= 1:
    keyboard = []
    for i in range(0, len(addy), 2):
      row = []
      for j in range(2):
        if i + j < len(addy):
          link = addy[i + j]
          button = types.InlineKeyboardButton(
            text=f"Wallet {i + j + 1}",
            url=f"https://etherscan.io/address/{link}")
          row.append(button)
      keyboard.append(row)
    reply_markup = types.InlineKeyboardMarkup(keyboard)
    bot.send_message(message.chat.id,
                     f"<b><i>{msg}.</i></b>",
                     reply_markup=reply_markup,
                     parse_mode="html")
  addy = []


@bot.message_handler(commands=['start'])
def greet(message):
  emoji = '\U0000274C'
  if message.chat.id not in allowed:
    bot.send_message(
      message.chat.id,
      f"<b>Access Denied</b> {emoji}. <i>Buy .5% supply of Smart Ai Token and send your user id <tg-spoiler><b><u>{message.chat.id}</u></b></tg-spoiler> to @WenCGWenCMC</i>",
      parse_mode="html")
    return
  #elif message.text.startswith('/start') and message.text.split(
  #  " ")[1].startswith('?'):
  #start_msg = message.text[len("/start "):]
  #mainSabkaBaap(message, start_msg)
  else:
    bot.send_photo(message.chat.id, "https://ibb.co/JjWc7dK")
    bot.send_message(
      message.chat.id,
      f"<b>Welcome To Smart Wallet  Ai Bot.</b> \n \nThis Bot is used for checking how many fresh wallets are buying a certain contract\n\n<i>use /ca then contract to check the contract for new buys\nuse /list to get list of early wallets that bought the seached token</i>\n\nBot Dev :- @WenCGWenCMC",
      parse_mode="html")


def get_holders(array_of_objects, key):
  return [obj[key] for obj in array_of_objects]


def get_contract_holders(message, contract_address):
  a = []
  api_key = "GFe9A3lNYWFSv1jO5NmC14bUHeW4oedryp1BPUHxAnAMZUL7C3Nd0Ppjaru3003R"
  params = {
    "addresses": [contract_address],
    "chain": "eth",
  }

  result = evm_api.token.get_token_metadata(
    api_key=api_key,
    params=params,
  )

  #print(result)
  name = result[0]['name']
  symbol = result[0]['symbol']
  decimal = result[0]['decimals']
  a = []
  contract_address = w3.toChecksumAddress(contract_address)
  try:
    topic_hash = Web3.keccak(text='Transfer(address,address,uint256)').hex()
    event_filter = w3.eth.filter({
      'fromBlock': 0,
      'toBlock': 'latest',
      'address': contract_address,
      'topics': [topic_hash]
    })
    transfer_events = event_filter.get_all_entries()[3:150]
    for event in transfer_events:
      toAds = "0x" + (event['topics'][2].hex())[26:]
      if toAds.lower() != contract_address.lower():
        a.append(toAds)
  except:
    bot.send_message(message.chat.id, f"You're Querying a very old token")
  if len(a) == 0:
    bot.send_message(
      message.chat.id,
      f"<b>Some error occured maybe the contract is not live yet try again with a diffrent ca </b>",
      parse_mode="html")
    return

  #a = list(set(a))
  #b = a[:5]
  #print(b)

  tx_counts = get_tx_counts(a)
  print(tx_counts)
  less_than_50 = [
    wallet for wallet, count in tx_counts.items() if count > 1 and count < 51
  ]
  less_than_20 = [
    wallet for wallet, count in tx_counts.items() if count > 1 and count < 21
  ]

  less_than_10 = [
    wallet for wallet, count in tx_counts.items() if count > 1 and count < 11
  ]
  addy = less_than_10
  less_than_5 = [
    wallet for wallet, count in tx_counts.items() if count > 1 and count < 5
  ]
  #print(less_than_5)
  less_than_3 = [
    wallet for wallet, count in tx_counts.items() if count > 1 and count < 4
  ]
  print("3")
  lenLessThan3 = len(less_than_3)
  lenLessThan5 = len(less_than_5)
  lenLessThan10 = len(less_than_10)
  lenLessThan20 = len(less_than_20)
  lenLessThan50 = len(less_than_50)
  #print(lenLessThan10)
  percentage = round((lenLessThan20 / len(a)) * 100, 2)
  contractCheckKrlo = f"<a href='https://etherscan.io/token/{contract_address}'>Contract</a>"
  dexSc = f"<a href='https://dexscreener.com/ethereum/{contract_address}'>DexScreener</a>"
  dextools = f"<a href='https://www.dextools.io/app/en/ether/pair-explorer/{contract_address}'>Dextools</a>"
  #print(percentage)
  emojiHit = "\U0001F3AF"
  round_percentage = round(percentage, 2)
  #alphaHits = checkedCa[contract_address]
  buyMaestro = f"<a href='https://t.me/MaestroSniperBot?start={contract_address}'>Maestro</a>"
  dataaddy = json.dumps({"addy": contract_address})
  #dataWallet = str(b)
  #callback_data_wallet = json.dumps(dataWallet)
  #print(dataWallet)
  keyboard = telebot.types.InlineKeyboardMarkup()
  button = telebot.types.InlineKeyboardButton(
    "Click Here For Info About The Token", callback_data=dataaddy)
  #button2 = telebot.types.InlineKeyboardButton("Early Buyer Wallet Address",
  #                                            callback_data=dataWallet)
  keyboard.add(button)

  bot.send_message(
    message.chat.id,
    f"Fresh Wallets 💎 Analysis By Smart Wallet AI\n\n<i>{name}</i> <i>({symbol}) ETH</i>\nDecimals:- <i>{decimal}</i>\nCA:- <pre>{contract_address}</pre>\n\nDetailed Analysis of holders 🔍\n\nLess Than 50 transactions :- <i>{lenLessThan50}</i>\nLess Than 20 transactions :- <i>{lenLessThan20}</i>\nless Than 10 transactions :- <i>{lenLessThan10}</i>\nless Than 5 transactions :- {lenLessThan5}\n\nNumber of wallets Checked :- {len(a)}\n\nPercentage of fresh wallet:- {percentage}%\n\n{buyMaestro} | {dextools} | {contractCheckKrlo}",
    parse_mode="html",
    reply_markup=keyboard,
    disable_web_page_preview=True)


@bot.callback_query_handler(func=lambda call: True)
def additional_info_handler(call):
  data = (call.data)
  message = call.message
  if 'addy' in data:
    data = json.loads(data)
    ca = data['addy']
    mainSabkaBaap(message, ca)
  if data == "reward":
    rewardCa(message)
  elif data == "zero":
    print("zero")
  elif data == "rebase":
    print("rebase")


def rewardCa(message):
  bot.reply_to(message, f"<b>Enter Your Token Name</b>", parse_mode="html")
  bot.register_next_step_handler(message, get_token_name)


def get_token_name(message):
  name = message.text
  bot.reply_to(message, f"<b>Enter Your Token Ticker</b>", parse_mode="html")
  bot.register_next_step_handler(message, get_ticker, name)


def get_ticker(message, name):
  symbol = message.text
  bot.reply_to(message,
               f"<b>Enter Marketing Wallet address</b>",
               parse_mode="html")
  bot.register_next_step_handler(message, get_marketing, name, symbol)


def get_marketing(message, name, symbol):
  mw = message.text
  try:
    if mw.startswith("0x"):
      mw = w3.toChecksumAddress(mw)
      print(mw, name, symbol)
      bot.reply_to(message,
                   f"<b>Enter Contract Address Of Reward Token</b>",
                   parse_mode="html")
      bot.register_next_step_handler(message, get_reward_token, name, symbol,
                                     mw)

    else:
      bot.reply_to(
        message,
        "Sorry, that's not a valid address. Please enter your address again.")
      bot.register_next_step_handler(message, get_marketing, name, symbol)
      return
  except:
    bot.reply_to(
      message,
      "Sorry, that's not a valid address. Please enter your address again.")
    bot.register_next_step_handler(message, get_marketing, name, symbol)
    return


def get_reward_token(message, name, symbol, mw):
  rewardCa = message.text
  if not rewardCa.startswith("0x"):
    bot.reply_to(
      message,
      "Sorry, that's not a valid token. Please enter token address again.")
    bot.register_next_step_handler(message, get_reward_token, name, symbol, mw)
    return
  else:
    try:
      rewardCa = w3.toChecksumAddress(rewardCa)
      bot.reply_to(
        message,
        f"<b>Enter Liqudity, Marketing, Reward Tax in same order seprated by spaces for example 2 5 3</b>",
        parse_mode="html")
      bot.register_next_step_handler(message, get_taxes, name, symbol, mw,
                                     rewardCa)
    except:
      bot.reply_to(
        message,
        "Sorry, that's not a valid token. Please enter token address again.")
      bot.register_next_step_handler(message, get_reward_token, name, symbol,
                                     mw)
      return


def get_taxes(message, name, symbol, mw, rewardCa):
  try:
    tax = message.text
    lpTax = int(tax.split(" ")[0])
    mwTax = int(tax.split(" ")[1])
    rewTax = int(tax.split(" ")[2])
    SUM = (lpTax + mwTax + rewTax)
    if SUM > 15:
      bot.reply_to(message, "Total tax cannot be more than 15%.")
      bot.register_next_step_handler(message, get_taxes, name, symbol, mw,
                                     rewardCa)
      return
    else:
      bot.reply_to(
        message,
        f"<b>Name:- </b> <i>{name}</i>\n\n<b>Symbol:-</b> <i>{symbol}</i>\n\n<b>Marketing Wallet:-</b> <pre>{mw}</pre>\n\n<b>Reward Token</b>:- <i><pre>{rewardCa}</pre></i>\n\n<b>Taxes</b>\n\nLiqudity:- {lpTax}\nMarketing:- {mwTax}\nRewards:- {rewTax}\n\n<b><u>If Everything is correct type YES else type NO to restart</u></b>",
        parse_mode="html")
      bot.register_next_step_handler(message, get_final, name, symbol, mw,
                                     rewardCa, lpTax, mwTax, rewTax)
  except:
    bot.reply_to(message,
                 "Looks like you didnt use the correct format try again.")
    bot.register_next_step_handler(message, get_taxes, name, symbol, mw,
                                   rewardCa)
    return


def get_final(message, name, symbol, mw, rewards, lp, mwtax, rew):
  reply = message.text

  if reply.lower() == "yes":
    filename = 'code.txt'
    with open(filename, 'r') as f:
      lines = f.readlines()
    line_number = 354
    line_number_symbol = 355
    line_reward = 361
    line_marketing = 434
    line_lp = 376
    line_mw = 377
    line_rw = 378
    new_line_lp = f'    uint256 public liquidityFee = {lp};\n'
    new_line_mw = f'    uint256 public marketingFee = {mwtax};\n'
    new_line_rw = f'    uint256 public rewardsFee = {rew};\n'
    new_line_marketing = f'        anothermarketingWallet = {mw};\n'
    new_line_reward = f'    address RewardToken = {rewards};\n'
    new_line_symbol = f'    string constant _symbol = "{symbol}";\n'
    new_line = f'    string constant _name = "{name}";\n'
    lines[line_number - 1] = new_line
    lines[line_number_symbol - 1] = new_line_symbol
    lines[line_reward - 1] = new_line_reward
    lines[line_marketing - 1] = new_line_marketing
    lines[line_lp - 1] = new_line_lp
    lines[line_mw - 1] = new_line_mw
    lines[line_rw - 1] = new_line_rw

    with open(filename, 'w') as f:
      f.writelines(lines)
    with open(filename, 'rb') as f:
      bot.send_document(message.chat.id, f)
  elif reply.lower() == "no":
    rewardCa(message)


def get_balance(addy):
  one = 0
  point = 0
  three = 0
  five = 0
  for ad in addy:
    checksummed_addr = Web3.toChecksumAddress(ad)
    balance = round(w3.eth.get_balance(checksummed_addr) / 10**18, 2)
    if balance <= .5:
      point = point + 1
    elif balance > .5 and balance <= 1:
      one = one + 1
    elif balance >= 1 and balance <= 3:
      three = three + 1
    else:
      five = five + 1


def get_tx_count(address):
  checksummed_addr = Web3.toChecksumAddress(address)
  count = w3.eth.get_transaction_count(checksummed_addr)
  return count


def get_tx_counts(addresses):
  tx_counts = {}
  for address in addresses:
    tx_counts[address] = get_tx_count(address)

  print("slow")
  return tx_counts


@bot.message_handler(commands=["ca"])
def echo_message(message):
  global checkedCa
  emojiHi = '\U0001F44B'
  emojiClock = '\U0001F551'
  if message.chat.id not in allowed:
    bot.send_message(message.chat.id, "Access Denied.")
    return
  print(message.text)
  user_name = message.from_user.first_name
  if not message.text.split(" ")[1].startswith("0x"):
    bot.send_message(
      message.chat.id,
      f"<tg-spoiler><b><i>Hey, I Know you have nothing to do in life apart from shitcoins but i have a life pls send correct ca</i></b></tg-spoiler>",
      parse_mode="html")
  else:
    contract_address = message.text.split(" ")[1]
    bot.send_message(
      message.chat.id,
      f"<i><b>Hey! {user_name} {emojiHi} Searching Your Query Might take up to 30 secs{emojiClock}!</b></i>",
      parse_mode="html")
    if contract_address in checkedCa:
      #print(checkedCa)
      checkedCa[contract_address] = checkedCa[contract_address] + 1
      cache_data(checkedCa, checkedCa_cache)
    else:
      #print(checkedCa)
      checkedCa[contract_address] = 1
      #print(checkedCa)
      cache_data(checkedCa, checkedCa_cache)
    get_contract_holders(message, contract_address)


def getTaxes(caInfo):
  buyTax = False
  sellTax = False
  ca = w3.toChecksumAddress(caInfo)
  url = f"https://api.etherscan.io/api?module=contract&action=getabi&address={ca}"
  response = requests.get(url)
  #print(response)
  if response.status_code == 200:
    abi = response.json()
    #print(abi)
    abi = response.json()["result"]
    if abi == 'Contract source code not verified':
      return abi
    contract = w3.eth.contract(address=ca, abi=abi)
    name = contract.all_functions()
    #print(name)
    for func in name:
      if str(func) == "<Function buyTotalFees()>":
        buyTax = contract.functions.buyTotalFees().call()
      if str(func) == "<Function sellTotalFees()>":
        sellTax = contract.functions.sellTotalFees().call()

  return [buyTax, sellTax]


@bot.message_handler(commands=["wallet"])
def walletAll(message):
  if message.text.split(" ")[1].startswith("0x"):
    wallet = message.text.split(" ")[1]
    walletValue(message, wallet)


def walletValue(message, wallet):
  freeKey2 = "EK-8RsfJ-ckCnNW5-ddbmS"
  try:
    url = f"https://api.ethplorer.io/getAddressInfo/{wallet}?apiKey={freeKey2}&showETHTotals=true"
    res = requests.get(url)
    data = res.text
    realD = json.loads(data)
    #print(realD)
    ethPrice = realD['ETH']['price']['rate']
    ethBalance = realD['ETH']['balance']
    ethPrice = round(ethPrice, 2)
    ethBalance = round(ethBalance, 2)
    totalUsd = round(ethPrice * ethBalance, 1)
    transactions = realD['countTxs']
    addressWallet = f"<a href ='etherscan.io/address/{wallet}'>Wallet</a>"
    opArr = []
    url5 = f"https://api.ethplorer.io/getAddressHistory/{wallet}?apiKey={freeKey}&type=transfer&limit=40"
    res5 = requests.get(url5)
    data5 = res5.text
    realData5 = json.loads(data5)
    hashess = realData5['operations']
    bpArr = []
    for hash in hashess:
      bpArr.append(hash['transactionHash'].lower())

    new_list = []
    for item in bpArr:
      if item not in new_list:
        new_list.append(item)
    for fresh in new_list:
      url2 = f"https://api.ethplorer.io/getTxInfo/{fresh}?apiKey={freeKey2}"
      #realh = w3.eth.get_transaction_receipt(fresh['transaction_hash'])
      #print(realh)
      res = requests.get(url2)
      data = res.text
      #print(data)
      realD = json.loads(data)
      opArr.append(realD)
      str = ""
      profit = 0

    opArr = opArr[:40]
    for op in opArr:
      lengthLelo = len(op["operations"])
      name = op["operations"][lengthLelo - 1]["tokenInfo"]['name']
      if name == "WETH":
        lengthHJi = len(op['operations'])
        value = op['operations'][lengthHJi - 1]['value']
        value = int(value) / 10**18
        value = round(value, 3)
        naam = op['operations'][0]['tokenInfo']['name']
        if naam == "WETH":
          continue
        address = op['operations'][0]['tokenInfo']['address']
        address = f"https://etherscan.io/token/{address}"
        stylenaam = f"<a href='{address}'>{naam}</a>"
        hash = op["hash"]
        hash = f"https://etherscan.io/tx/{hash}"
        hashLink = f"<a href='{hash}'>hash</a>"
        str = str + f"Sold {stylenaam} for {value}eth at {hashLink}\n\n"
        profit = profit + value

      else:
        weth = op["operations"][0]['tokenInfo']['name']
        length = len(op["operations"])
        if weth == "WETH":
          name = op["operations"][length - 1]['tokenInfo']['name']
          address = op["operations"][length - 1]['tokenInfo']['address']
          address = f"https://etherscan.io/token/{address}"
          stylenaam = f"<a href='{address}'>{name}</a>"
          value = op["operations"][0]['value']
          value = int(value) / 10**18
          value = round(value, 3)
          hash = op['hash']
          hash = f"https://etherscan.io/tx/{hash}"
          hashLink = f"<a href='{hash}'>hash</a>"
          str = str + f"Bought {stylenaam} for {value}eth at {hashLink}\n\n"
          profit = profit - value

    profit = round(profit, 3)
    bot.send_message(
      message.chat.id,
      f"{addressWallet} <b><i><pre>{wallet}</pre></i></b>\n\n<b>Basic Info</b>\n\n<i>Balance:- {ethBalance}eth\nUsdValue:- ${totalUsd}\nTotal Transactions:-{transactions}\n\n<b>Latest 20 Tokens Buys And Sells</b>\n\n{str}\n</i><b>Totals Profits Made:- </b> <i>{profit}eth</i>\n\n<b><u>Note:-The user might still be holding his tokens so profits could be negative</u></b>",
      parse_mode="html",
      disable_web_page_preview=True)
  except:
    bot.send_message(
      message.chat.id,
      f"<b><u>Some error occured check for <pre> {wallet}</pre></u></b>",
      parse_mode="html")


def time_diff_to_dhm(timestamp):
  """
    Calculates the time difference between the current time and a timestamp, and returns the result in days, hours, and minutes format.
    """
  # Get current time in Unix format
  current_time = datetime.datetime.now().timestamp()

  # Calculate time difference in seconds
  diff_seconds = int(current_time - timestamp)

  # Calculate number of days, hours, and minutes
  days, remaining_seconds = divmod(diff_seconds, 86400)
  hours, remaining_seconds = divmod(remaining_seconds, 3600)
  minutes, remaining_seconds = divmod(remaining_seconds, 60)

  # Return formatted string
  return f"{days} days, {hours} hours, {minutes} minutes"


@bot.message_handler(commands=["gas"])
def pending(message):

  url = 'https://min-api.cryptocompare.com/data/price?fsym=ETH&tsyms=USD'
  response = requests.get(url)
  data = response.json()
  eth_price_usd = data['USD']
  print(eth_price_usd)
  gas = w4.eth.gas_price
  gasGwei = gas / 10**9
  gasGwei = round(gasGwei)
  highGas = round(gasGwei * 1.2)

  bot.send_message(
    message.chat.id,
    f"<b><u>Ethereum Gas Fees </u></b>\n\n<b>Low</b>:- <i>{gasGwei} GWEI</i>\n<b>Average</b>:- <i>{gasGwei} GWEI</i>\n<b>High</b>:- <i>{highGas} GWEI</i>",
    parse_mode="html")


def checkDeploy(transactionsD, ca):
  contract_count = 0
  info = ""
  for transaction in transactionsD:
    if transaction['contractAddress'] != "" and transaction[
        'contractAddress'].lower() != ca.lower():

      contract_count = contract_count + 1
      contractG = transaction['contractAddress']
      print(contractG)
      urll = f"https://api.ethplorer.io/getTokenInfo/{contractG}?apiKey={freeKey}"
      ress = requests.get(urll)
      dataa = ress.text
      realDd = json.loads(dataa)
      if "error" in realDd:
        return " "
      holdersCheck = int(realDd["holdersCount"])
      if holdersCheck > 30:
        addyOtherDeploy = realDd['address']
        addyOtherDeployL = f"https://dexscreener.com/ethereum/{addyOtherDeploy}"
        namee = realDd['name']
        linkk = f"<a href='{addyOtherDeployL}'>{namee}</a>"
        info = info + f"{linkk} launched from this wallet and has {holdersCheck} holders\n"
  return info


def larp(message, ca):
  api_key = "GFe9A3lNYWFSv1jO5NmC14bUHeW4oedryp1BPUHxAnAMZUL7C3Nd0Ppjaru3003R"
  params = {
    "addresses": [ca],
    "chain": "eth",
  }

  result = evm_api.token.get_token_metadata(
    api_key=api_key,
    params=params,
  )
  #print(result)
  keyboard = [[
    types.InlineKeyboardButton(
      "Dextools",
      url=f"https://www.dextools.io/app/en/ether/pair-explorer/{ca}"),
    types.InlineKeyboardButton("DexScreener",
                               url=f"https://dexscreener.com/ethereum/{ca}")
  ],
              [
                types.InlineKeyboardButton(
                  "Honeypot Checker",
                  url=f"https://honeypot.is/ethereum?address={ca}"),
                types.InlineKeyboardButton(
                  "Buy Using Maestro",
                  url=f"https://t.me/MaestroSniperBot?start={ca}")
              ]]
  reply_markup = types.InlineKeyboardMarkup(keyboard)
  caAddy = f"https://etherscan.io/token/{ca}"
  caAddy = f"<a href='{caAddy}'>{ca}</a>"
  caName = result[0]['name']
  caSymbol = result[0]['symbol']
  if "created_at" in result[0]:

    caLaunchedAt = result[0]['created_at'].split("T")[0]
    caSecsLaunched = result[0]['created_at'].split("T")[1].split(".")[0]
    caSecsLaunched = f"{caLaunchedAt}  {caSecsLaunched}"

  deployer = checkDeployer(ca)
  freeKey2 = "EK-8RsfJ-ckCnNW5-ddbmS"
  url = f"https://api.ethplorer.io/getAddressInfo/{deployer}?apiKey={freeKey2}&showETHTotals=true"

  deployerW = f"https://etherscan.io/address/{deployer}"
  deployerW = f"<a href='{deployerW}'>{deployer}</a>"
  res = requests.get(url)
  data = res.text
  realD = json.loads(data)
  ethPrice = realD['ETH']['price']['rate']
  ethBalance = realD['ETH']['balance']
  ethPrice = round(ethPrice, 2)
  ethBalance = float(round(ethBalance, 2))
  totalUsd = float(round(ethPrice * ethBalance, 1))
  transactions = realD['countTxs']
  str = ""
  if "tokens" in realD:
    tokens = realD['tokens']
    str = "Deployer wallet holds these tokens\n"
    for token in tokens:
      print(token["tokenInfo"])
      tokenInfo = token['tokenInfo']

      addy = tokenInfo['address']
      addyDex = f"https://etherscan.io/token/{addy}"
      name = tokenInfo['name']
      decimal = int(tokenInfo["decimals"])
      decimal = 10**decimal
      totalSupply = int(tokenInfo['totalSupply'])
      totalSupply = totalSupply / decimal
      balance = int(token["balance"])
      balance = balance / decimal
      if totalSupply == 0:
        continue
      else:
        share = round((balance / totalSupply) * 100, 1)

      if share < 0.00001:
        continue
      link = f"<a href='{addyDex}'>{name}</a> has {share}% of supply"
      str = f"{str} {link}\n"
    str = f"{str}\n"

  url2 = f"https://api.etherscan.io/api?module=account&action=txlist&address={deployer}&startblock=0&endblock=99999999&sort=asc&apikey=7UMIKS3MQXWYW975VTPF84Y25EDW4B2NXA"
  response = requests.get(url2)
  data = response.json()
  transactionsD = data['result']
  #transactions = transactions[::-1]
  funder = transactionsD[0]["from"]
  info = checkDeploy(transactionsD, ca)

  funderW = f"https://etherscan.io/address/{funder}"
  funderW = f"<a href='{funderW}'>{funder}</a>"
  hash = transactionsD[0]['hash']
  hash = f"https://etherscan.io/tx/{hash}"
  hash = f"<a href='{hash}'>Hash</a>"
  value = int(transactionsD[0]['value'])
  value = value / 10**18
  timeStamp = int(transactionsD[0]['timeStamp'])
  date = time_diff_to_dhm(timeStamp)

  url3 = f"https://api.ethplorer.io/getAddressInfo/{funder}?apiKey={freeKey2}&showETHTotals=true"
  res = requests.get(url3)
  data = res.text
  realD = json.loads(data)
  #print(realD)
  ethPriceFunder = realD['ETH']['price']['rate']
  ethBalanceFunder = realD['ETH']['balance']
  ethPriceFunder = round(ethPriceFunder, 2)
  ethBalanceFunder = round(ethBalanceFunder, 2)
  totalUsdFunder = round(ethPriceFunder * ethBalanceFunder, 1)
  transactionsFunder = int(realD['countTxs'])
  tokensFunder = ""
  strFunder = ""

  if transactionsFunder > 10000:
    #print(str)
    report = "Likely Funded From A Exchange"
    #print(info)
    bot.send_message(
      message.chat.id,
      f"CA :- <pre>{caAddy}</pre>\n\n<i>{caName} </i><i>({caSymbol}) ETH</i>\n\nDeployerWallet:- <i>{deployerW}</i>\n\nWalletBalance:- <i>{ethBalance}</i> ETH (<i>${totalUsd}</i>)\nTotalTranscation:- <i>{transactions}</i>\nWallet is {date} old\n\n{str}\nFunded From:- <i>{funderW}</i>\nTotalEth:- <i>{ethBalanceFunder}eth</i>\nUsdValue:- <i>{totalUsdFunder}</i>\nTotal Transactins:- <i>{transactionsFunder}\n\n</i><u>{report}</u>",
      parse_mode="html",
      disable_web_page_preview=True,
      reply_markup=reply_markup)
  else:
    strFunder = ""
    if "tokens" in realD:
      tokensFunder = realD['tokens']
      strFunder = "Wallet holds these tokens\n"
      for token in tokensFunder:
        print(token["tokenInfo"])
        tokenInfoFunder = token['tokenInfo']
        addyFunder = tokenInfoFunder['address']
        addyDexFunder = f"https://etherscan.io/tok/{addyFunder}"
        if "name" in tokenInfoFunder:
          nameFunder = tokenInfoFunder['name']
        decimal = int(tokenInfoFunder["decimals"])
        decimal = 10**decimal
        totalSupply = int(tokenInfoFunder['totalSupply'])
        totalSupply = totalSupply / decimal
        balance = int(token["balance"])
        balance = balance / decimal
        shareFunder = round((balance / totalSupply) * 100, 1)
        linkFunder = f"<a href='{addyDexFunder}'>{nameFunder}</a> has {shareFunder}% of supply"
        strFunder = f"{strFunder} {linkFunder}\n"
    strFunder = f"{strFunder}\n"
    url4 = f"https://api.etherscan.io/api?module=account&action=txlist&address={funder}&startblock=0&endblock=99999999&sort=asc&apikey=7UMIKS3MQXWYW975VTPF84Y25EDW4B2NXA"
    response = requests.get(url4)
    data = response.json()
    transactionsFunderFunder = data['result']
    infoFunder = checkDeploy(transactionsFunderFunder, ca)
    #transactions = transactions[::-1]
    funderFunder = transactionsFunderFunder[0]["from"]
    timeStamp = int(transactionsD[0]['timeStamp'])
    dateFF = time_diff_to_dhm(timeStamp)
    funderFunderW = f"https://etherscan.io/address/{funderFunder}"
    funderFunderW = f"<a href='{funderFunderW}'>{funderFunder}</a>"
    url5 = f"https://api.ethplorer.io/getAddressInfo/{funderFunder}?apiKey={freeKey2}&showETHTotals=true"
    res = requests.get(url5)
    data = res.text
    realD = json.loads(data)
    ethPriceFunderFunder = realD['ETH']['price']['rate']
    ethBalanceFunderFunder = realD['ETH']['balance']
    ethPriceFunderFunder = round(ethPriceFunderFunder, 2)
    ethBalanceFunderFunder = round(ethBalanceFunderFunder, 2)
    totalUsdFunderFunder = round(ethPriceFunderFunder * ethBalanceFunderFunder,
                                 1)
    transactionsFunderFunder = int(realD['countTxs'])

    #tokensFunderFunder = realD['tokens']
    bot.send_message(
      message.chat.id,
      f"CA:-<pre> {caAddy}</pre>\n\n<i>{caName}</i><i> ({caSymbol}) ETH</i>\n\nDeployerWallet:- <i>{deployerW}</i>\n\nWalletBalance:- <i>{ethBalance}</i> eth <i>(${totalUsd}</i>)\nTotalTranscation:- <i>{transactions}</i>\nWallet is {date} old\n\n{str}{info}\nFunded From:-<i>{funderW}</i>\nTotalEth:- <i>{ethBalanceFunder}</i>eth\nUsdValue:- <i>{totalUsdFunder}</i>\nTotal Transactins:- <i>{transactionsFunder}</i>\n{infoFunder}Wallet is {dateFF} old\n\n{strFunder}\nFunded From:- <i>{funderFunderW}</i>\nBalance:- <i>{ethBalanceFunderFunder}</i>\nUsdValue:- <i>${totalUsdFunderFunder}</i>\nTotal Transactions:- <i>{transactionsFunderFunder}\n</i>",
      parse_mode="html",
      disable_web_page_preview=True,
      reply_markup=reply_markup)


@bot.message_handler(commands=["larp"])
def getLarp(message):
  ca = message.text.split(" ")[1]
  larp(message, ca)


def getDetails(token, deployer, unlockDate):
  url = f"https://api.etherscan.io/api?module=account&action=tokentx&address={token}&startblock=0&endblock=999999999&sort=asc&apikey={ethApi}"
  response = requests.get(url)
  data = response.json()
  #print(data)
  #token_ca = data["result"][0]["contractAddress"]
  name = data["result"][0]['tokenName']
  buy = f"https://t.me/MaestroSniperBot?start={token}"
  chart = f"<a href='https://dexscreener.com/ethereum/{token}'>Dexscreener</a>"
  #info = f"https://t.me/SmartWalletAiBot?start={token_ca}"
  #infoM = f"<a href='{info}'>Click Here To Get Detailed Info</a>"
  buyM = f"<a href='{buy}'>Maestro</a>"
  unlock = time_diff_to_dhm(unlockDate)
  unlock = unlock[1:].split(",")[0]
  str = f"{name}\nCA:- <pre>{token}</pre>\nLocked for:- {unlock} \n{buyM} | {chart}\n\n--------------------------------------------------\n"
  return str


@bot.message_handler(commands=['early'])
def early(message):
  a = []
  ca = message.text.split(" ")[1]
  ca = w3.toChecksumAddress(ca)
  mssg = f"First 10 early buyers wallets of the token you seached"
  topic_hash = Web3.keccak(text='Transfer(address,address,uint256)').hex()
  event_filter = w3.eth.filter({
    'fromBlock': 0,
    'toBlock': 'latest',
    'address': ca,
    'topics': [topic_hash]
  })
  transfer_events = event_filter.get_all_entries()[3:85]
  for event in transfer_events:
    toAds = "0x" + (event['topics'][2].hex())[26:]

    if toAds.lower() != ca.lower():
      print(toAds)
      a.append(toAds)
      #print(a)

  print(a)
  #a = list(set(a))
  print(a)
  b = a[:10]
  c = []
  for item in a:
    if item not in c:
      c.append(item)
  greetings(b, message, mssg)
  for wallet in c:
    walletValue(message, wallet)


@bot.message_handler(commands=['locked'])
def lockCheck(message):
  text = f"<b><u>5 Most Recent Locked Tokens on Unicript</u></b>\n\n"
  contract_address = '0x663A5C229c09b049E36dCc11a9B0d4a8Eb9db214'
  contract_abi = abiLp
  contract_team = "0xE2fE530C047f2d85298b07D9333C05737f1435fB"
  contract_abiTeam = abiTeam
  contractTeam = w3.eth.contract(address=contract_team, abi=contract_abiTeam)
  contract = w3.eth.contract(address=contract_address, abi=contract_abi)
  latest_block = w3.eth.getBlock('latest').number
  events = contract.events.onDeposit().createFilter(
    fromBlock=latest_block - 10000,
    toBlock='latest').get_all_entries()[-1:-6:-1]
  for event in events:
    token = event['args']['lpToken']
    deployer = event["args"]['user']
    unlockDate = event['args']['unlockDate']
    str = getDetails(token, deployer, unlockDate)
    text = text + str

  bot.send_message(message.chat.id,
                   f"{text}",
                   parse_mode="html",
                   disable_web_page_preview=True)
  print(contractTeam.events)


@bot.message_handler(commands=['deepCheck'])
def deep(message):
  addy = "0x6990fbA44edb1CE375cD5C0f436f8f51F1623cdC"
  url = f"https://api.ethplorer.io/getAddressHistory/{addy}?apiKey={freeKey}&token=0xB7f0F8FE4eddc86a1f650c024dB58b3F8CcD3076"
  res = requests.get(url)
  data = res.text
  realD = json.loads(data)
  hash = realD["operations"][0]["transactionHash"]
  url2 = f"https://api.ethplorer.io/getTxInfo/{hash}?apiKey={freeKey}"
  res2 = requests.get(url2)
  data2 = res2.text
  realD2 = json.loads(data2)
  print(realD2)


@bot.message_handler(commands=["deploy"])
def latest(message):
  markup = types.InlineKeyboardMarkup(row_width=1)
  reward_button = types.InlineKeyboardButton("Reward Token",
                                             callback_data='reward')
  zero_button = types.InlineKeyboardButton("Zero Tax", callback_data='zero')
  rebase_button = types.InlineKeyboardButton("Rebase Token",
                                             callback_data='rebase')
  markup.add(reward_button, zero_button, rebase_button)
  bot.send_message(message.chat.id,
                   "<b>Select Which Type Of Contract You Want</b>:",
                   reply_markup=markup,
                   parse_mode="html")


@bot.message_handler(func=lambda message: True)
def handleAll(message):
  if message.text.startswith("0x"):
    contract_address = message.text
    get_contract_holders(message, contract_address)


bot.polling()
