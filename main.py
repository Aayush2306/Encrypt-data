import telebot
import requests
import json
from telebot import types
from web3 import Web3
from moralis import evm_api
import datetime
from abi import abiLp

from Crypto.Cipher import ChaCha20
from Crypto.Util.Padding import pad, unpad
import os
from abi import abiTeam

key = os.urandom(32)
nonce = os.urandom(8)
Api_Key = "6128069220:AAGwBaVvB6lZO21ha6wnFCdvHpI8UhzlcIU"
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
  str = f"{name}\nLp Pair Address:- <pre>{token}</pre>\nLocked for:- {unlock} \n{buyM} | {chart}\n--------------------------------------------------------\n"
  return str


def checkDeployer(caInfo):
  url = f"https://api.etherscan.io/api?module=account&action=txlist&address={caInfo}&startblock=0&endblock=99999999&sort=asc&apiKey=7UMIKS3MQXWYW975VTPF84Y25EDW4B2NXA"
  response = requests.get(url)
  data = response.json()
  #print(data)
  deployer = (data['result'][0]['from'])
  return deployer


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
    "https://ibb.co/QMCtgfM",
    caption=
    f"<b>Welcome To Encryption 🔐 Ai Bot .</b> \n \nThis Bot is used for encrypting a contract address into a format which snipers, telegram scrappers cant detect so the launch is without bots.\n\n<i>use /encrypt then contract address to encrypt the contract \nuse /decrypt to get the contract address from encrypted message\nuse /larp then contract address to check if a token is larp and get various info\n</i>",
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
      decimal = int(tokenInfo["decimals"])
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


bot.polling()
