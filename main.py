import telebot
import requests
import json
from telebot import types
from web3 import Web3
from moralis import evm_api
import datetime
from abi import abiLp
import pickle
from mnemonic import Mnemonic
from Crypto.Cipher import ChaCha20
from Crypto.Util.Padding import pad, unpad
import os
from abi import abiTeam

key = os.urandom(32)
nonce = os.urandom(8)
Api_Key = "6128069220:AAGwBaVvB6lZO21ha6wnFCdvHpI8UhzlcIU"
#Api_Key = "6016921915:AAEdyj5pFBNoUCf1kIqCvQ1Su8ku9d2oJhs"
apii = "6221710889:AAGUxZLR80SzCuYg8KieAKGu05sVjXm-M2U"
bot = telebot.TeleBot(Api_Key)
mainData = {}
infura = "https://mainnet.infura.io/v3/c1f653384020470d942fdd4d8eb97795"
w3 = Web3(Web3.HTTPProvider(infura))
w4 = Web3(
  Web3.HTTPProvider(
    "https://shy-white-knowledge.discover.quiknode.pro/3dd1414d33024c972650675c3437e2a23c8db00f/"
  ))
moralis_key = "GFe9A3lNYWFSv1jO5NmC14bUHeW4oedryp1BPUHxAnAMZUL7C3Nd0Ppjaru3003R"
freeKey = "EK-cgMkq-f79VYYW-u1JY5"
ethApi = "7UMIKS3MQXWYW975VTPF84Y25EDW4B2NXA"
apikeyeth = "7UMIKS3MQXWYW975VTPF84Y25EDW4B2NXA"

ourTokenCa = "0x397b102deccace4aa8e5ba63eedb8e65ad83e20c"
allowed = []
addy_cache = 'addy.pickle'
file_name = 'cached_array.pickle'
addys_cache = 'addys.pickle'
addyVerified = []
verifiedAddyCache = {}
devid = [795341146]
wallets = []


def cache_data(data, file_name):
  with open(file_name, 'wb') as f:
    pickle.dump(data, f)


def load_cached_data(file_name):
  try:
    with open(file_name, 'rb') as f:
      return pickle.load(f)
  except FileNotFoundError:
    return None


#cache_data(allowed, file_name)
#cache_data(verifiedAddyCache, addy_cache)
#cache_data(wallets, addys_cache)
#print(verifiedAddyCache)
allowed = load_cached_data(file_name)
wallets = load_cached_data(addys_cache)
verifiedAddyCache = load_cached_data(addy_cache)
#print(allowed, wallets, verifiedAddyCache)


@bot.message_handler(commands=["verify"])
def verify(message):
  if message.from_user.id in allowed:
    bot.send_message(message.chat.id,
                     f"<b><i>You're Already Verified</i></b>",
                     parse_mode="html")
  else:
    #chat_id = latest_message["message"]["chat"]["id"]
    #print(chat_id)
    mnemo = Mnemonic("english")
    words = mnemo.generate(strength=256)
    seed = mnemo.to_seed(words, passphrase="")
    account = w3.eth.account.privateKeyToAccount(seed[:32])
    private_key = account.privateKey
    public_key = account.address
    private_key = private_key.hex()
    #public_key = int(public_key)
    bot.send_message(message.chat.id,
                     f"<b><i><pre>{public_key}</pre></i></b>",
                     parse_mode="html")
    sent_msg = bot.send_message(
      message.chat.id,
      f"<b><i>To Get Verified And Access To The bot Make Sure You Have more than 300 tokens.\n\nIf you have then copy the above wallet address and send 0 eth  to that address Wait for around 2-3 mins to get transaction added in blockchain or wait for 10 confirmations. \n\nThen reply to this msg  with your transaction hash </i></b> ",
      parse_mode="html",
    )
    bot.register_next_step_handler(message,
                                   process_name_step,
                                   data={'publicKey': public_key})


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


def process_name_step(message, data):
  hash = message.text
  public_key = data["publicKey"]
  if hash.startswith("0x"):
    #print("hi", hash)
    checkTxHash(hash, message, public_key)
  elif hash.startswith("http"):
    #print("hlo", hash)
    newTx = hash.split("/")[4]
    checkTxHash(newTx, message, public_key)
  else:
    bot.send_message(message.chat.id, f"Thats not a transaction hash")


def checkTxHash(tx, message, public_key):
  global wallets
  global verifiedAddyCache
  global allowed
  global ourTokenCa
  maestro = f"<a href='https://t.me/maestrosniperbot/?start={ourTokenCa}'>Maestro</a>"
  public_key = public_key.lower()
  try:
    url = f"https://api.ethplorer.io/getTxInfo/{tx}?apiKey={freeKey}"
    res = requests.get(url)
    data = res.text
    realD = json.loads(data)
    toAddy = realD['to']
    fromAddy = realD['from']
    toAddy = toAddy.lower()
    fromAddy = fromAddy.lower()
    print(toAddy, fromAddy)
  except:
    bot.send_message(
      message.chat.id,
      f"<b><i> This dosent seem like a valid transaction hash</i></b>",
      parse_mode="html")
    return

  if toAddy == public_key and fromAddy not in wallets:
    urlCheck = f"https://api.etherscan.io/api?module=account&action=tokenbalance&contractaddress={ourTokenCa}&address={fromAddy}&tag=latest&apikey=H2IA5SV98N5KVTCIDE65KI3EECYRHNUYNF"

    print(url)
    response = requests.get(urlCheck)
    datac = response.text
    print(datac)
    balance = json.loads(datac)['result']
    balanceint = int(balance) / 10**9
    print(balanceint)
    if balanceint >= 300:
      id = int(message.from_user.id)
      username = message.chat.username
      bot.send_animation(
        message.chat.id,
        animation="https://media.giphy.com/media/veHIwhDRl780wT2XfC/giphy.gif",
        caption=f"<b>Verification SuccessFul.✅ </b>",
        parse_mode="html")
      allowed.append(id)
      wallets.append(fromAddy)
      verifiedAddyCache[fromAddy] = username
      bot_id = 795341146
      #print(bot_id)
      bot.send_message(
        bot_id,
        f"User Verified\n id = {message.chat.id},\nAddy = <pre>{fromAddy}</pre>\nUsername:- @{username}",
        parse_mode="html")
      cache_data(allowed, file_name)
      cache_data(verifiedAddyCache, addy_cache)
      cache_data(wallets, addys_cache)
    else:
      bot.send_message(
        message.chat.id,
        f"You dont have sufficent tokens. Use The link below to buy\n  {maestro} or buy with <pre>{ourTokenCa}</pre>",
        parse_mode="html")
  else:
    bot.send_message(
      message.chat.id,
      "<b>Either You are already Verified or sent eth to a wrong address</b>",
      parse_mode="html")


@bot.message_handler(commands=['check'])
def checkDev(message):
  global verifiedAddyCache
  global wallets
  text = f"<b><u>List of Address Who Sold</u></b>\n\n"
  if message.chat.id not in devid:
    bot.send_message(
      message.chat.id,
      f"<b><i>This command can only used by dev.\nUse /verify to get verified and get acess to whale chat</i></b>",
      parse_mode="html")
  else:
    addy = verifiedAddyCache.keys()
    for addy in verifiedAddyCache:
      api = f"https://api.etherscan.io/api?module=account&action=tokenbalance&contractaddress={ourTokenCa}&address={addy}&tag=latest&apikey=H2IA5SV98N5KVTCIDE65KI3EECYRHNUYNF"
      response = requests.get(api)
      username = verifiedAddyCache[addy]
      datac = response.text
      balance = int(json.loads(datac)['result'])
      balanceR = balance / 10**9
      if balanceR < 300:
        wallets.remove(addy)
        verifiedAddyCache.pop(addy)
        text = f"{text} <pre>{addy}</pre>\nUsername:-@{username}\n\n"
    bot.send_message(message.chat.id, f"{text}", parse_mode="html")


def getDetails(token, deployer, unlockDate, lockDate):
  try:
    
    url = f"https://api.etherscan.io/api?module=account&action=tokentx&address={token}&startblock=0&endblock=999999999&sort=asc&apikey={ethApi}"
    response = requests.get(url)
    data = response.json()
    #print(data)
    #token_ca = data["result"][0]["contractAddress"]
    name = data["result"][0]['tokenName']
    buy = f"https://t.me/MaestroSniperBot?start={token}"
    chart = f"<a href='https://dexscreener.com/ethereum/{token}'>DexSc</a>"
    #info = f"https://t.me/SmartWalletAiBot?start={token_ca}"
    #infoM = f"<a href='{info}'>Click Here To Get Detailed Info</a>"
    buyM = f"<a href='{buy}'>Maestro</a>"
    locker = f"https://app.uncx.network/amm/uni-v2/pair/{token}"
    lockLink = f"<a href='{locker}'>Lock Link</a>"
    unlock = time_diff_to_dhm(unlockDate)
    lockedat = time_diff_to_dhm(lockDate)
    lockedatHr = lockedat.split(",")[1]
    lockedatMin = lockedat.split(",")[2]
    if lockedatHr.startswith("0"):
      lala = ""
    else:
      lala = f"{lockedatHr} {lockedatMin}"

    unlock = unlock[1:].split(",")[0]
    str = f"{name}\n\nLp Pair Address:- <pre>{token}</pre>\n\nLocked {lala} ago\nLocked for:- {unlock} \n{buyM} | {chart} | {lockLink}\n----------------------------------------------------\n"
    return str
  except:
    print("no")



def checkDeployer(caInfo):
  try:
    url = f"https://api.etherscan.io/api?module=account&action=txlist&address={caInfo}&startblock=0&endblock=99999999&sort=asc&apiKey=7UMIKS3MQXWYW975VTPF84Y25EDW4B2NXA"
    response = requests.get(url)
    data = response.json()
    #print(data)
    deployer = (data['result'][0]['from'])
    return deployer
  except:
    print("no")


def encrypt_chacha20(plaintext):
  cipher = ChaCha20.new(key=key, nonce=nonce)
  ciphertext = cipher.encrypt(pad(plaintext.encode(), ChaCha20.block_size))
  return ciphertext, nonce


def decrypt_chacha20(ciphertext, nonce):
  cipher = ChaCha20.new(key=key, nonce=nonce)
  plaintext = unpad(cipher.decrypt(ciphertext), ChaCha20.block_size).decode()
  return plaintext


@bot.message_handler(commands=['early'])
def early(message):
  try:
    a = []
    ca = message.text.split(" ")[1].lower()
    cas = w3.toChecksumAddress(ca)
    dexurl = f"https://api.dexscreener.com/latest/dex/tokens/{ca}"
    ress = requests.get(dexurl)
    deta = ress.text
    realRes = json.loads(deta)
    url = f'https://api.etherscan.io/api?module=account&action=txlist&address={ca}&startblock=0&endblock=99999999&sort=asc&apikey={ethApi}'
    response = requests.get(url)
    response_json = response.json()
    transaction_hash = response_json['result'][0]['hash']

    url = f'https://api.etherscan.io/api?module=proxy&action=eth_getTransactionByHash&txhash={transaction_hash}&apikey={ethApi}'
    response = requests.get(url)
    response_json = response.json()
    block_number_hex = response_json['result']['blockNumber']
    block_number = int(block_number_hex, 16)
    latest_block_number = int(w3.eth.blockNumber)
    next_block = block_number + 10000
    if latest_block_number < next_block:
      next_block = latest_block_number

    name = (realRes['pairs'][0]['baseToken']['name'])
    symbol = (realRes['pairs'][0]['baseToken']['symbol'])
    topic_hash = Web3.keccak(text='Transfer(address,address,uint256)').hex()
    event_filter = w3.eth.filter({
    'fromBlock': block_number,
    'toBlock': next_block,
    'address': cas,
    '  topics': [topic_hash]
  })
    transfer_events = event_filter.get_all_entries()[3:100]
    for event in transfer_events:
      if len(event['topics']) < 3:
        continue
    #print(event['topics'])
      toAds = "0x" + (event['topics'][2].hex())[26:]

      if toAds.lower() != ca.lower():
      #print(toAds)
        if toAds not in a:
          a.append(toAds)
  #print(a)
    b = a[:10]
    z = looper(b, ca)
    bot.send_message(message.chat.id,
                   f"First 10 Buyer of {name} ({symbol})\n\n{z}",
                   parse_mode="html",
                   disable_web_page_preview=True)
    k = a[10:20]
  #print(c)
    d = looper(k, ca)
    bot.send_message(message.chat.id,
                   f"10 - 20 Buyer of {name} ({symbol})\n\n{d}",
                   parse_mode="html",
                   disable_web_page_preview=True)
  #print(d)
    e = a[20:30]
    l = looper(e, ca)
    bot.send_message(message.chat.id,
                   f"20 - 30 Buyer of {name} ({symbol})\n\n{l}",
                   parse_mode="html",
                   disable_web_page_preview=True)
  
  except:
    print("no")
    
def looper(b, ca):
  try:
    a = ""
    for wallet in b:
      url = f"https://api.ethplorer.io/getAddressInfo/{wallet}?apiKey={freeKey}&token={ca}"
    #print(url)
      res = requests.get(url)
      data = res.text
      realD = json.loads(data)
      if "tokens" not in realD:
        continue
      if realD["tokens"] == []:
        w = w3.toChecksumAddress(wallet)
        balance = w3.eth.getBalance(w)
        balance = round(float(balance / 10**18), 2)
        fresh = w3.eth.getTransactionCount(w)
        if fresh < 20:
          f = "Fresh Wallet :- ✅"
        else:
          f = "Fresh Wallet :- ❌"
        addy = f"<a href ='etherscan.io/address/{wallet}'>Address</a>"
        a = a + f"{addy} :- <pre>{wallet}</pre>\nStill Holding :- ❌\nBalance :- {balance} ETH\n{f}\n\n"
      else:
        w = w3.toChecksumAddress(wallet)
        balance = w3.eth.getBalance(w)
        balance = round(float(balance / 10**18), 2)
      #print(balance)
        fresh = w3.eth.getTransactionCount(w)
        if fresh < 20:
          f = "Fresh Wallet :- ✅"
        else:
          f = "Fresh Wallet :- ❌"
        addy = f"<a href ='etherscan.io/address/{wallet}'>Address</a>"
        a = a + f"{addy} :- <pre>{wallet}</pre>\nStill Holding :- ✅\nBalance :- {balance} ETH\n{f}\n\n"

    return a
  except:
    print("no")


def greetings(addy, message, msg):
  try:
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
  except:
    print("no")


@bot.message_handler(commands=['start'])
def greet(message):
  if message.from_user.id not in allowed:
    bot.send_message(
      message.chat.id,
      f"You're not verified.To get access make sure you have 300 $0xEncrypt Tokens and then type /verify"
    )
    return
  bot.send_photo(
    message.chat.id,
    "https://ibb.co/QMCtgfM",
    caption=
    f"<b>Welcome To Encryption 🔐 Ai Bot .</b> \n \nThis Bot is used for encrypting a contract address into a format which snipers, telegram scrappers cant detect so the launch is without bots.\n\n<i>use /encrypt then contract address to encrypt the contract \nuse /decrypt to get the contract address from encrypted message\nuse /larp then contract address to check if a token is larp and get various info\nuse /locked to get 5 latest token whose lp is locked on unicrypt\nuse /find amd the token name to find telegram of the token\nuse /wallet and wallet address to get last 20 ERC 20 txs of the wallet</i>",
    parse_mode="html")


@bot.message_handler(commands=['encrypt'])
def encrypt(message):
  try:
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
  except:
    print("no")


@bot.message_handler(commands=['decrypt'])
def decrypt(message):
  try:
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
  except:
    print("no")


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
  try:
    api_key = "OtQHsL737I5UrQcznOs5FTU89BD46bwDdxlPvLN3ct4VC2uKhVqg1Hqluh4qMnUL"
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
    #if "created_at" in result[0]:
    # print(result[0])
    #caLaunchedAt = result[0]['created_at'].split("T")[0]
    #caSecsLaunched = result[0]['created_at'].split("T")[1].split(".")[0]
    #caSecsLaunched = f"{caLaunchedAt}  {caSecsLaunched}"

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
      if len(tokens) > 0:
        str = "Deployer wallet holds these tokens\n"
      for token in tokens:
        print(token["tokenInfo"])
        tokenInfo = token['tokenInfo']

        addy = tokenInfo['address']
        addyDex = f"https://etherscan.io/token/{addy}"
        name = tokenInfo['name']
        if name.startswith("Uniswap V"):
          name = "Liqiuidity"

        if "decimals" in tokenInfo:
          decimal = int(tokenInfo["decimals"])
        else:
          continue
        #decimal = int(tokenInfo["decimals"])
        decimal = 10**decimal
        totalSupply = int(tokenInfo['totalSupply'])
        totalSupply = totalSupply / decimal
        balance = int(token["balance"])
        balance = balance / decimal
        print(name)
        if totalSupply == 0:
          continue
        else:
          share = round((balance / totalSupply) * 100, 1)

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
      totalUsdFunderFunder = round(
        ethPriceFunderFunder * ethBalanceFunderFunder, 1)
      transactionsFunderFunder = int(realD['countTxs'])

      #tokensFunderFunder = realD['tokens']
      bot.send_message(
        message.chat.id,
        f"CA:-<pre> {caAddy}</pre>\n\n<i>{caName}</i><i> ({caSymbol}) ETH</i>\n\nDeployerWallet:- <i>{deployerW}</i>\n\nWalletBalance:- <i>{ethBalance}</i> eth <i>(${totalUsd}</i>)\nTotalTranscation:- <i>{transactions}</i>\nWallet is {date} old\n\n{str}{info}\nFunded From:-<i>{funderW}</i>\nTotalEth:- <i>{ethBalanceFunder}</i>eth\nUsdValue:- <i>{totalUsdFunder}</i>\nTotal Transactins:- <i>{transactionsFunder}</i>\n{infoFunder}Wallet is {dateFF} old\n\n{strFunder}\nFunded From:- <i>{funderFunderW}</i>\nBalance:- <i>{ethBalanceFunderFunder}</i>\nUsdValue:- <i>${totalUsdFunderFunder}</i>\nTotal Transactions:- <i>{transactionsFunderFunder}\n</i>",
        parse_mode="html",
        disable_web_page_preview=True,
        reply_markup=reply_markup)
  except:
    print("no")


@bot.message_handler(commands=["larp"])
def getLarp(message):
  if message.from_user.id not in allowed:
    return
  try:
    ca = message.text.split(" ")[1].lower()
    larp(message, ca)
  except:
    print("no")


@bot.message_handler(commands=['locked'])
def lockCheck(message):
  if message.from_user.id not in allowed:
    return
  try:
    text = f"<b><u>5 Most Recent Locked Tokens on Unicrypt</u></b>\n\n"
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
      #print(event)
      token = event['args']['lpToken']
      deployer = event["args"]['user']
      unlockDate = event['args']['unlockDate']
      lockDate = event['args']['lockDate']
      str = getDetails(token, deployer, unlockDate, lockDate)
      text = text + str

    keyboard = types.InlineKeyboardMarkup()
    button = types.InlineKeyboardButton(text='Refresh',
                                        callback_data='refresh')
    keyboard.add(button)
    bot.send_message(
      message.chat.id,
      f"{text}",
      parse_mode="html",
      disable_web_page_preview=True,
    )
  except:
    print("no")


@bot.message_handler(commands=["find"])
def find(message):
  if message.from_user.id not in allowed:
    return
  try:
    foundTg = []
    tgs = []
    tg = message.text.split(" ")[1]
    tgs = [
      f"@{tg}", f"@{tg}official", f"@{tg}coin", f"@{tg}token", f"@{tg}_cn",
      f"@{tg}_eth", f"@{tg}crypto", f"@{tg}portal", f"@{tg}_portal",
      f"@{tg}Erc", f"@{tg}_erc", f"@{tg}erc20", f"@{tg}_erc20", f"@{tg}entry",
      f"@{tg}_token", f"@{tg}_bsc"
    ]
    print(tgs)
    for tg in tgs:
      try:
        url = f'https://api.telegram.org/bot{apii}/getChat?chat_id={tg}'
        response = requests.get(url).json()
        if response['ok'] == True:
          foundTg.append(tg)

      except telebot.apihelper.ApiTelegramException as e:
        print(e)
    print(foundTg)
    if foundTg == []:
      msg = ""
      for tg in tgs:
        print(tg)
        msg = f"{msg}{tg}\n"
      bot.send_message(
        message.chat.id,
        f"No Telegram Group Found from the input.Try again in a few mins.")
    else:
      msg = ""
      for tg in foundTg:
        msg = f"{msg}{tg}\n"
      bot.send_message(message.chat.id,
                       f"<u>Possible Telegram Groups:-</u>\n\n{msg}",
                       parse_mode="html")
  except:
    print("no")


@bot.message_handler(commands=["wallet"])
def walletAll(message):
  if message.from_user.id not in allowed:
    return
  try:
    if message.text.split(" ")[1].startswith("0x"):
      wallet = message.text.split(" ")[1]
      walletValue(message, wallet)
  except:
    print("noo")


def get_tx_count(address):
  try:
    checksummed_addr = Web3.toChecksumAddress(address)
    count = w3.eth.get_transaction_count(checksummed_addr)
    return count
  except:
    print("bo")


def get_tx_counts(addresses):
  try:
    tx_counts = {}
    for address in addresses:
      tx_counts[address] = get_tx_count(address)

    print("slow")
    return tx_counts
  except:
    print("noo")


def get_contract_holders(message, contract_address):
  try:
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
      f"Fresh Wallets Analysis 🔐n\n<i>{name}</i> <i>({symbol}) ETH</i>\nDecimals:- <i>{decimal}</i>\nCA:- <pre>{contract_address}</pre>\n\nDetailed Analysis of holders 🔍\n\nLess Than 50 transactions :- <i>{lenLessThan50}</i>\nLess Than 20 transactions :- <i>{lenLessThan20}</i>\nless Than 10 transactions :- <i>{lenLessThan10}</i>\nless Than 5 transactions :- {lenLessThan5}\n\nNumber of wallets Checked :- {len(a)}\n\nPercentage of fresh wallet:- {percentage}%\n\n{buyMaestro} | {dextools} | {contractCheckKrlo}",
      parse_mode="html",
      reply_markup=keyboard,
      disable_web_page_preview=True)
  except:
    print("noo")


@bot.callback_query_handler(func=lambda call: True)
def additional_info_handler(call):
  data = (call.data)
  message = call.message
  if 'addy' in data:
    data = json.loads(data)
    ca = data['addy']
    mainSabkaBaap(message, ca)


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


def get_holders(array_of_objects, key):
  return [obj[key] for obj in array_of_objects]


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


@bot.message_handler(commands=["ca"])
def echo_message(message):
  if message.from_user.id not in allowed:
    return
  try:
    global checkedCa
    emojiHi = '\U0001F44B'
    emojiClock = '\U0001F551'
    user_name = message.from_user.first_name
    if not message.text.split(" ")[1].startswith("0x"):
      bot.send_message(
        message.chat.id,
        f"<tg-spoiler><b><i>Hey,  pls send correct ca</i></b></tg-spoiler>",
        parse_mode="html")
    else:
      contract_address = message.text.split(" ")[1].lower()
      get_contract_holders(message, contract_address)
  except:
    print("no")


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
    url5 = f"https://api.ethplorer.io/getAddressHistory/{wallet}?apiKey={freeKey}&type=transfer&limit=30"
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

    opArr = opArr[:20]
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
      f"{addressWallet} <b><i><pre>{wallet}</pre></i></b>\n\n<b>Basic Info</b>\n\n<i>Balance:- {ethBalance}eth\nUsdValue:- ${totalUsd}\nTotal Transactions:-{transactions}\n\n<b>Latest 20 Tokens Buys And Sells</b>\n\n{str}\n</i><b>Totals Profits Made: </b> <i>{profit}eth</i>\n\n<b><u>Note:-The user might still be holding his tokens so profits could be negative</u></b>",
      parse_mode="html",
      disable_web_page_preview=True)
  except:
    bot.send_message(
      message.chat.id,
      f"<b><u>Some error occured check for <pre> {wallet}</pre></u></b>",
      parse_mode="html")


bot.polling()
