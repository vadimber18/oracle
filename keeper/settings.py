from decouple import config
from web3 import Web3

from common.settings import GOERLI, MAINNET, NETWORK

WEB3_ENDPOINT = config("WEB3_ENDPOINT")

ORACLE_PRIVATE_KEY = config("ORACLE_PRIVATE_KEY")

PROCESS_INTERVAL = config("PROCESS_INTERVAL", default=180, cast=int)

TRANSACTION_TIMEOUT = config("TRANSACTION_TIMEOUT", default=900, cast=int)

if NETWORK == MAINNET:
    ORACLES_CONTRACT_ADDRESS = Web3.toChecksumAddress(
        "0x0000000000000000000000000000000000000000"
    )
    MULTICALL_CONTRACT_ADDRESS = Web3.toChecksumAddress(
        "0xeefBa1e63905eF1D7ACbA5a8513c70307C1cE441"
    )
elif NETWORK == GOERLI:
    ORACLES_CONTRACT_ADDRESS = Web3.toChecksumAddress(
        "0x0000000000000000000000000000000000000000"
    )
    MULTICALL_CONTRACT_ADDRESS = Web3.toChecksumAddress(
        "0x77dCa2C955b15e9dE4dbBCf1246B4B85b651e50e"
    )
