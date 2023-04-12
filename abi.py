abiLp = [{
  "inputs": [{
    "internalType": "contract IUniFactory",
    "name": "_uniswapFactory",
    "type": "address"
  }],
  "stateMutability":
  "nonpayable",
  "type":
  "constructor"
}, {
  "anonymous":
  False,
  "inputs": [{
    "indexed": True,
    "internalType": "address",
    "name": "previousOwner",
    "type": "address"
  }, {
    "indexed": True,
    "internalType": "address",
    "name": "newOwner",
    "type": "address"
  }],
  "name":
  "OwnershipTransferred",
  "type":
  "event"
}, {
  "anonymous":
  False,
  "inputs": [{
    "indexed": False,
    "internalType": "address",
    "name": "lpToken",
    "type": "address"
  }, {
    "indexed": False,
    "internalType": "address",
    "name": "user",
    "type": "address"
  }, {
    "indexed": False,
    "internalType": "uint256",
    "name": "amount",
    "type": "uint256"
  }, {
    "indexed": False,
    "internalType": "uint256",
    "name": "lockDate",
    "type": "uint256"
  }, {
    "indexed": False,
    "internalType": "uint256",
    "name": "unlockDate",
    "type": "uint256"
  }],
  "name":
  "onDeposit",
  "type":
  "event"
}, {
  "anonymous":
  False,
  "inputs": [{
    "indexed": False,
    "internalType": "address",
    "name": "lpToken",
    "type": "address"
  }, {
    "indexed": False,
    "internalType": "uint256",
    "name": "amount",
    "type": "uint256"
  }],
  "name":
  "onWithdraw",
  "type":
  "event"
}, {
  "inputs": [],
  "name":
  "gFees",
  "outputs": [{
    "internalType": "uint256",
    "name": "ethFee",
    "type": "uint256"
  }, {
    "internalType": "contract IERCBurn",
    "name": "secondaryFeeToken",
    "type": "address"
  }, {
    "internalType": "uint256",
    "name": "secondaryTokenFee",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "secondaryTokenDiscount",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "liquidityFee",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "referralPercent",
    "type": "uint256"
  }, {
    "internalType": "contract IERCBurn",
    "name": "referralToken",
    "type": "address"
  }, {
    "internalType": "uint256",
    "name": "referralHold",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "referralDiscount",
    "type": "uint256"
  }],
  "stateMutability":
  "view",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "uint256",
    "name": "_index",
    "type": "uint256"
  }],
  "name":
  "getLockedTokenAtIndex",
  "outputs": [{
    "internalType": "address",
    "name": "",
    "type": "address"
  }],
  "stateMutability":
  "view",
  "type":
  "function"
}, {
  "inputs": [],
  "name":
  "getNumLockedTokens",
  "outputs": [{
    "internalType": "uint256",
    "name": "",
    "type": "uint256"
  }],
  "stateMutability":
  "view",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "address",
    "name": "_lpToken",
    "type": "address"
  }],
  "name":
  "getNumLocksForToken",
  "outputs": [{
    "internalType": "uint256",
    "name": "",
    "type": "uint256"
  }],
  "stateMutability":
  "view",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "address",
    "name": "_user",
    "type": "address"
  }, {
    "internalType": "address",
    "name": "_lpToken",
    "type": "address"
  }, {
    "internalType": "uint256",
    "name": "_index",
    "type": "uint256"
  }],
  "name":
  "getUserLockForTokenAtIndex",
  "outputs": [{
    "internalType": "uint256",
    "name": "",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "",
    "type": "uint256"
  }, {
    "internalType": "address",
    "name": "",
    "type": "address"
  }],
  "stateMutability":
  "view",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "address",
    "name": "_user",
    "type": "address"
  }, {
    "internalType": "uint256",
    "name": "_index",
    "type": "uint256"
  }],
  "name":
  "getUserLockedTokenAtIndex",
  "outputs": [{
    "internalType": "address",
    "name": "",
    "type": "address"
  }],
  "stateMutability":
  "view",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "address",
    "name": "_user",
    "type": "address"
  }],
  "name":
  "getUserNumLockedTokens",
  "outputs": [{
    "internalType": "uint256",
    "name": "",
    "type": "uint256"
  }],
  "stateMutability":
  "view",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "address",
    "name": "_user",
    "type": "address"
  }, {
    "internalType": "address",
    "name": "_lpToken",
    "type": "address"
  }],
  "name":
  "getUserNumLocksForToken",
  "outputs": [{
    "internalType": "uint256",
    "name": "",
    "type": "uint256"
  }],
  "stateMutability":
  "view",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "address",
    "name": "_user",
    "type": "address"
  }],
  "name":
  "getUserWhitelistStatus",
  "outputs": [{
    "internalType": "bool",
    "name": "",
    "type": "bool"
  }],
  "stateMutability":
  "view",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "uint256",
    "name": "_index",
    "type": "uint256"
  }],
  "name":
  "getWhitelistedUserAtIndex",
  "outputs": [{
    "internalType": "address",
    "name": "",
    "type": "address"
  }],
  "stateMutability":
  "view",
  "type":
  "function"
}, {
  "inputs": [],
  "name":
  "getWhitelistedUsersLength",
  "outputs": [{
    "internalType": "uint256",
    "name": "",
    "type": "uint256"
  }],
  "stateMutability":
  "view",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "address",
    "name": "_lpToken",
    "type": "address"
  }, {
    "internalType": "uint256",
    "name": "_index",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "_lockID",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "_amount",
    "type": "uint256"
  }],
  "name":
  "incrementLock",
  "outputs": [],
  "stateMutability":
  "nonpayable",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "address",
    "name": "_lpToken",
    "type": "address"
  }, {
    "internalType": "uint256",
    "name": "_amount",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "_unlock_date",
    "type": "uint256"
  }, {
    "internalType": "address payable",
    "name": "_referral",
    "type": "address"
  }, {
    "internalType": "bool",
    "name": "_fee_in_eth",
    "type": "bool"
  }, {
    "internalType": "address payable",
    "name": "_withdrawer",
    "type": "address"
  }],
  "name":
  "lockLPToken",
  "outputs": [],
  "stateMutability":
  "payable",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "address",
    "name": "_lpToken",
    "type": "address"
  }, {
    "internalType": "uint256",
    "name": "_index",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "_lockID",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "_amount",
    "type": "uint256"
  }],
  "name":
  "migrate",
  "outputs": [],
  "stateMutability":
  "nonpayable",
  "type":
  "function"
}, {
  "inputs": [],
  "name":
  "owner",
  "outputs": [{
    "internalType": "address",
    "name": "",
    "type": "address"
  }],
  "stateMutability":
  "view",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "address",
    "name": "_lpToken",
    "type": "address"
  }, {
    "internalType": "uint256",
    "name": "_index",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "_lockID",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "_unlock_date",
    "type": "uint256"
  }],
  "name":
  "relock",
  "outputs": [],
  "stateMutability":
  "nonpayable",
  "type":
  "function"
}, {
  "inputs": [],
  "name": "renounceOwnership",
  "outputs": [],
  "stateMutability": "nonpayable",
  "type": "function"
}, {
  "inputs": [{
    "internalType": "address payable",
    "name": "_devaddr",
    "type": "address"
  }],
  "name":
  "setDev",
  "outputs": [],
  "stateMutability":
  "nonpayable",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "uint256",
    "name": "_referralPercent",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "_referralDiscount",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "_ethFee",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "_secondaryTokenFee",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "_secondaryTokenDiscount",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "_liquidityFee",
    "type": "uint256"
  }],
  "name":
  "setFees",
  "outputs": [],
  "stateMutability":
  "nonpayable",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "contract IMigrator",
    "name": "_migrator",
    "type": "address"
  }],
  "name":
  "setMigrator",
  "outputs": [],
  "stateMutability":
  "nonpayable",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "contract IERCBurn",
    "name": "_referralToken",
    "type": "address"
  }, {
    "internalType": "uint256",
    "name": "_hold",
    "type": "uint256"
  }],
  "name":
  "setReferralTokenAndHold",
  "outputs": [],
  "stateMutability":
  "nonpayable",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "address",
    "name": "_secondaryFeeToken",
    "type": "address"
  }],
  "name":
  "setSecondaryFeeToken",
  "outputs": [],
  "stateMutability":
  "nonpayable",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "address",
    "name": "_lpToken",
    "type": "address"
  }, {
    "internalType": "uint256",
    "name": "_index",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "_lockID",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "_amount",
    "type": "uint256"
  }],
  "name":
  "splitLock",
  "outputs": [],
  "stateMutability":
  "payable",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "address",
    "name": "",
    "type": "address"
  }, {
    "internalType": "uint256",
    "name": "",
    "type": "uint256"
  }],
  "name":
  "tokenLocks",
  "outputs": [{
    "internalType": "uint256",
    "name": "lockDate",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "amount",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "initialAmount",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "unlockDate",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "lockID",
    "type": "uint256"
  }, {
    "internalType": "address",
    "name": "owner",
    "type": "address"
  }],
  "stateMutability":
  "view",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "address",
    "name": "_lpToken",
    "type": "address"
  }, {
    "internalType": "uint256",
    "name": "_index",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "_lockID",
    "type": "uint256"
  }, {
    "internalType": "address payable",
    "name": "_newOwner",
    "type": "address"
  }],
  "name":
  "transferLockOwnership",
  "outputs": [],
  "stateMutability":
  "nonpayable",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "address",
    "name": "newOwner",
    "type": "address"
  }],
  "name":
  "transferOwnership",
  "outputs": [],
  "stateMutability":
  "nonpayable",
  "type":
  "function"
}, {
  "inputs": [],
  "name":
  "uniswapFactory",
  "outputs": [{
    "internalType": "contract IUniFactory",
    "name": "",
    "type": "address"
  }],
  "stateMutability":
  "view",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "address",
    "name": "_user",
    "type": "address"
  }, {
    "internalType": "bool",
    "name": "_add",
    "type": "bool"
  }],
  "name":
  "whitelistFeeAccount",
  "outputs": [],
  "stateMutability":
  "nonpayable",
  "type":
  "function"
}, {
  "inputs": [{
    "internalType": "address",
    "name": "_lpToken",
    "type": "address"
  }, {
    "internalType": "uint256",
    "name": "_index",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "_lockID",
    "type": "uint256"
  }, {
    "internalType": "uint256",
    "name": "_amount",
    "type": "uint256"
  }],
  "name":
  "withdraw",
  "outputs": [],
  "stateMutability":
  "nonpayable",
  "type":
  "function"
}]

abiTeam = [{
  "constant": False,
  "inputs": [{
    "name": "newImplementation",
    "type": "address"
  }],
  "name": "upgradeTo",
  "outputs": [],
  "payable": False,
  "stateMutability": "nonpayable",
  "type": "function"
}, {
  "constant":
  False,
  "inputs": [{
    "name": "newImplementation",
    "type": "address"
  }, {
    "name": "data",
    "type": "bytes"
  }],
  "name":
  "upgradeToAndCall",
  "outputs": [],
  "payable":
  True,
  "stateMutability":
  "payable",
  "type":
  "function"
}, {
  "constant": False,
  "inputs": [],
  "name": "implementation",
  "outputs": [{
    "name": "",
    "type": "address"
  }],
  "payable": False,
  "stateMutability": "nonpayable",
  "type": "function"
}, {
  "constant": False,
  "inputs": [{
    "name": "newAdmin",
    "type": "address"
  }],
  "name": "changeAdmin",
  "outputs": [],
  "payable": False,
  "stateMutability": "nonpayable",
  "type": "function"
}, {
  "constant": False,
  "inputs": [],
  "name": "admin",
  "outputs": [{
    "name": "",
    "type": "address"
  }],
  "payable": False,
  "stateMutability": "nonpayable",
  "type": "function"
}, {
  "inputs": [{
    "name": "_logic",
    "type": "address"
  }, {
    "name": "_admin",
    "type": "address"
  }, {
    "name": "_data",
    "type": "bytes"
  }],
  "payable":
  True,
  "stateMutability":
  "payable",
  "type":
  "constructor"
}, {
  "payable": True,
  "stateMutability": "payable",
  "type": "fallback"
}, {
  "anonymous":
  False,
  "inputs": [{
    "indexed": False,
    "name": "previousAdmin",
    "type": "address"
  }, {
    "indexed": False,
    "name": "newAdmin",
    "type": "address"
  }],
  "name":
  "AdminChanged",
  "type":
  "event"
}, {
  "anonymous":
  False,
  "inputs": [{
    "indexed": True,
    "name": "implementation",
    "type": "address"
  }],
  "name":
  "Upgraded",
  "type":
  "event"
}]

abiUni = [{
  "inputs": [{
    "internalType": "address",
    "name": "_feeToSetter",
    "type": "address"
  }],
  "payable":
  False,
  "stateMutability":
  "nonpayable",
  "type":
  "constructor"
}, {
  "anonymous":
  False,
  "inputs": [{
    "indexed": True,
    "internalType": "address",
    "name": "token0",
    "type": "address"
  }, {
    "indexed": True,
    "internalType": "address",
    "name": "token1",
    "type": "address"
  }, {
    "indexed": False,
    "internalType": "address",
    "name": "pair",
    "type": "address"
  }, {
    "indexed": False,
    "internalType": "uint256",
    "name": "",
    "type": "uint256"
  }],
  "name":
  "PairCreated",
  "type":
  "event"
}, {
  "constant":
  True,
  "inputs": [{
    "internalType": "uint256",
    "name": "",
    "type": "uint256"
  }],
  "name":
  "allPairs",
  "outputs": [{
    "internalType": "address",
    "name": "",
    "type": "address"
  }],
  "payable":
  False,
  "stateMutability":
  "view",
  "type":
  "function"
}, {
  "constant":
  True,
  "inputs": [],
  "name":
  "allPairsLength",
  "outputs": [{
    "internalType": "uint256",
    "name": "",
    "type": "uint256"
  }],
  "payable":
  False,
  "stateMutability":
  "view",
  "type":
  "function"
}, {
  "constant":
  False,
  "inputs": [{
    "internalType": "address",
    "name": "tokenA",
    "type": "address"
  }, {
    "internalType": "address",
    "name": "tokenB",
    "type": "address"
  }],
  "name":
  "createPair",
  "outputs": [{
    "internalType": "address",
    "name": "pair",
    "type": "address"
  }],
  "payable":
  False,
  "stateMutability":
  "nonpayable",
  "type":
  "function"
}, {
  "constant":
  True,
  "inputs": [],
  "name":
  "feeTo",
  "outputs": [{
    "internalType": "address",
    "name": "",
    "type": "address"
  }],
  "payable":
  False,
  "stateMutability":
  "view",
  "type":
  "function"
}, {
  "constant":
  True,
  "inputs": [],
  "name":
  "feeToSetter",
  "outputs": [{
    "internalType": "address",
    "name": "",
    "type": "address"
  }],
  "payable":
  False,
  "stateMutability":
  "view",
  "type":
  "function"
}, {
  "constant":
  True,
  "inputs": [{
    "internalType": "address",
    "name": "",
    "type": "address"
  }, {
    "internalType": "address",
    "name": "",
    "type": "address"
  }],
  "name":
  "getPair",
  "outputs": [{
    "internalType": "address",
    "name": "",
    "type": "address"
  }],
  "payable":
  False,
  "stateMutability":
  "view",
  "type":
  "function"
}, {
  "constant":
  False,
  "inputs": [{
    "internalType": "address",
    "name": "_feeTo",
    "type": "address"
  }],
  "name":
  "setFeeTo",
  "outputs": [],
  "payable":
  False,
  "stateMutability":
  "nonpayable",
  "type":
  "function"
}, {
  "constant":
  False,
  "inputs": [{
    "internalType": "address",
    "name": "_feeToSetter",
    "type": "address"
  }],
  "name":
  "setFeeToSetter",
  "outputs": [],
  "payable":
  False,
  "stateMutability":
  "nonpayable",
  "type":
  "function"
}]

value = {
  'anti_whale_modifiable':
  '1',
  'buy_tax':
  '0.089999',
  'can_take_back_ownership':
  '0',
  'cannot_buy':
  '0',
  'cannot_sell_all':
  '0',
  'creator_address':
  '0x1cddb101799d0795555b5806509988029a2b10e2',
  'creator_balance':
  '0',
  'creator_percent':
  '0.000000',
  'dex': [{
    'name': 'PancakeV2',
    'liquidity': '426.52364251',
    'pair': '0x09fe2d85ee05d56d9660cfc2f15eb2df167d25e7'
  }],
  'external_call':
  '0',
  'hidden_owner':
  '1',
  'holder_count':
  '87',
  'holders': [{
    'address': '0x09fe2d85ee05d56d9660cfc2f15eb2df167d25e7',
    'tag': 'PancakeV2',
    'is_contract': 1,
    'balance': '886420.1736154489',
    'percent': '0.886420173615448900',
    'is_locked': 0
  }, {
    'address': '0x52253f7c94dd27c9f7cc218d9d487a2af4b7add3',
    'tag': '',
    'is_contract': 0,
    'balance': '19684.185788019196',
    'percent': '0.019684185788019196',
    'is_locked': 0
  }, {
    'address': '0x2bc36f826e8fa826158c40b4a9ff085dd88cc6a9',
    'tag': '',
    'is_contract': 0,
    'balance': '17552.65079945413',
    'percent': '0.017552650799454130',
    'is_locked': 0
  }, {
    'address': '0xee541f7e9f8a5a633f5c041da66d6b8893574e73',
    'tag': '',
    'is_contract': 0,
    'balance': '17381.0',
    'percent': '0.017381000000000000',
    'is_locked': 0
  }, {
    'address': '0x60dffcde3a4d6242ce9a0c7c687facf6779774ea',
    'tag': '',
    'is_contract': 0,
    'balance': '13195.074187306203',
    'percent': '0.013195074187306203',
    'is_locked': 0
  }, {
    'address': '0x000000000000000000000000000000000000dead',
    'tag': '',
    'is_contract': 0,
    'balance': '9100.0',
    'percent': '0.009100000000000000',
    'is_locked': 1
  }, {
    'address': '0x1d31ca1903907f76c8dd53f4ec4dc24fc4a2ccc7',
    'tag': '',
    'is_contract': 0,
    'balance': '8840.357287325009',
    'percent': '0.008840357287325009',
    'is_locked': 0
  }, {
    'address': '0x6e9c09d31dcfee618159314d2393612f1c91d328',
    'tag': '',
    'is_contract': 0,
    'balance': '6291.884325593656',
    'percent': '0.006291884325593656',
    'is_locked': 0
  }, {
    'address': '0x8672daa8f36d15563cd670ad0bda3ac6fc3e0baa',
    'tag': '',
    'is_contract': 0,
    'balance': '4418.71257930641',
    'percent': '0.004418712579306410',
    'is_locked': 0
  }, {
    'address': '0x0e5ce321cf57e95d679e95c8de5778d500c62738',
    'tag': '',
    'is_contract': 0,
    'balance': '3329.072270541928',
    'percent': '0.003329072270541928',
    'is_locked': 0
  }],
  'honeypot_with_same_creator':
  '0',
  'is_anti_whale':
  '1',
  'is_blacklisted':
  '0',
  'is_honeypot':
  '0',
  'is_in_dex':
  '1',
  'is_mintable':
  '0',
  'is_open_source':
  '1',
  'is_proxy':
  '0',
  'is_whitelisted':
  '0',
  'lp_holder_count':
  '4',
  'lp_holders': [{
    'address': '0xae7e6cabad8d80f0b4e1c4dde2a5db7201ef1252',
    'tag': 'Mudra',
    'is_contract': 1,
    'balance': '1051.915029764464',
    'percent': '0.996813378187293724',
    'is_locked': 1
  }, {
    'address': '0x1cddb101799d0795555b5806509988029a2b10e2',
    'tag': '',
    'is_contract': 0,
    'balance': '2.327966240388397',
    'percent': '0.002206022184992574',
    'is_locked': 0
  }, {
    'address': '0x0ed943ce24baebf257488771759f9bf482c39706',
    'tag': '',
    'is_contract': 1,
    'balance': '1.034805018818402',
    'percent': '0.000980599627713755',
    'is_locked': 0
  }, {
    'address': '0x0000000000000000000000000000000000000000',
    'tag': '',
    'is_contract': 0,
    'balance': '0.000000000000001',
    'percent': '0.000000000000000000',
    'is_locked': 1
  }],
  'lp_total_supply':
  '1055.277801023670741999',
  'owner_address':
  '0x000000000000000000000000000000000000dead',
  'owner_balance':
  '9100',
  'owner_change_balance':
  '0',
  'owner_percent':
  '0.009100',
  'personal_slippage_modifiable':
  '0',
  'selfdestruct':
  '0',
  'sell_tax':
  '0.089431',
  'slippage_modifiable':
  '1',
  'token_name':
  'Whale Chat Bot',
  'token_symbol':
  'WHALE',
  'total_supply':
  '1000000',
  'trading_cooldown':
  '0',
  'transfer_pausable':
  '1'
}

{
  'buy_tax':
  '0.089999',
  'cannot_buy':
  '0',
  'cannot_sell_all':
  '0',
  'creator_address':
  '0x2b356a6c814673e42d1c27e988823ee0cab71d7c',
  'creator_balance':
  '148092.039518934859674089',
  'creator_percent':
  '0.014809',
  'dex': [{
    'name': 'PancakeV2',
    'liquidity': '4115.52149408',
    'pair': '0x48030aad16642aca5aefb9e86b999324bbf36054'
  }],
  'holder_count':
  '170',
  'holders': [{
    'address': '0x48030aad16642aca5aefb9e86b999324bbf36054',
    'tag': 'PancakeV2',
    'is_contract': 1,
    'balance': '1467925.57996171',
    'percent': '0.146792557996171000',
    'is_locked': 0
  }, {
    'address': '0x56315313a7226f284c433bf6ac6de176bacc3416',
    'tag': '',
    'is_contract': 1,
    'balance': '995000.0',
    'percent': '0.099500000000000000',
    'is_locked': 0
  }, {
    'address': '0x4c4ee8e5d81e6abc7b67f1da41f0cd7221d1061b',
    'tag': '',
    'is_contract': 1,
    'balance': '995000.0',
    'percent': '0.099500000000000000',
    'is_locked': 0
  }, {
    'address': '0x21b7f19a9cc5d1f39bbf6be3ff92f759b82135ad',
    'tag': '',
    'is_contract': 0,
    'balance': '149926.13999999998',
    'percent': '0.014992613999999998',
    'is_locked': 0
  }, {
    'address': '0x2b356a6c814673e42d1c27e988823ee0cab71d7c',
    'tag': '',
    'is_contract': 0,
    'balance': '148092.03951893485',
    'percent': '0.014809203951893485',
    'is_locked': 0
  }, {
    'address': '0xf36bbcbc4e19dbbd4a8fde0753c5f07ff4c11179',
    'tag': '',
    'is_contract': 0,
    'balance': '147636.38249260784',
    'percent': '0.014763638249260784',
    'is_locked': 0
  }, {
    'address': '0x84ed852a978627e89b4e492f8afd96cdbb939172',
    'tag': '',
    'is_contract': 0,
    'balance': '147154.93063135783',
    'percent': '0.014715493063135783',
    'is_locked': 0
  }, {
    'address': '0xda5e9c6976b29ec8dd75c1685499cdfd8c2e0289',
    'tag': '',
    'is_contract': 0,
    'balance': '146462.22962918348',
    'percent': '0.014646222962918348',
    'is_locked': 0
  }, {
    'address': '0xdbb7b27e4689716b5ae51c610e31214d3d1a5a5d',
    'tag': '',
    'is_contract': 0,
    'balance': '146226.10529775554',
    'percent': '0.014622610529775554',
    'is_locked': 0
  }, {
    'address': '0xf25c3d95fbb4c389000cf99c615000768c66a2b0',
    'tag': '',
    'is_contract': 0,
    'balance': '137982.7789511146',
    'percent': '0.013798277895111460',
    'is_locked': 0
  }],
  'honeypot_with_same_creator':
  '0',
  'is_in_dex':
  '1',
  'is_open_source':
  '0',
  'lp_holder_count':
  '5',
  'lp_holders': [{
    'address': '0xae7e6cabad8d80f0b4e1c4dde2a5db7201ef1252',
    'tag': 'Mudra',
    'is_contract': 1,
    'balance': '4120.203991515603',
    'percent': '0.971910727369400485',
    'is_locked': 1
  }, {
    'address': '0x2b356a6c814673e42d1c27e988823ee0cab71d7c',
    'tag': '',
    'is_contract': 0,
    'balance': '86.5482055651141',
    'percent': '0.020415768150441561',
    'is_locked': 0
  }, {
    'address': '0x5bd1774063da6836738fcab9131e34aeada4968f',
    'tag': '',
    'is_contract': 0,
    'balance': '20.704542670932675',
    'percent': '0.004883973504368845',
    'is_locked': 0
  }, {
    'address': '0x0ed943ce24baebf257488771759f9bf482c39706',
    'tag': '',
    'is_contract': 1,
    'balance': '11.82560942815365',
    'percent': '0.002789530975789243',
    'is_locked': 0
  }, {
    'address': '0x0000000000000000000000000000000000000000',
    'tag': '',
    'is_contract': 0,
    'balance': '0.000000000000001',
    'percent': '0.000000000000000000',
    'is_locked': 1
  }],
  'lp_total_supply':
  '4239.282349179802848592',
  'owner_address':
  '',
  'sell_tax':
  '0.099419',
  'token_name':
  'Otter Inu',
  'token_symbol':
  'OTTER',
  'total_supply':
  '10000000'
}
