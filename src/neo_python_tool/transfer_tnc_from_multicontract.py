
import binascii
import time

import requests
from base58 import b58decode
from neocore.BigInteger import BigInteger
from neocore.Cryptography.Crypto import Crypto
from neocore.UInt160 import UInt160
from neo.SmartContract.Contract import Contract



def ToScriptHash(address):
    data = b58decode(address)
    if len(data) != 25:
        raise ValueError('Not correct Address, wrong length.')
    if data[0] != 23:
        raise ValueError('Not correct Coin Version')

    checksum = Crypto.Default().Hash256(data[:21])[:4]
    if checksum != data[21:]:
        raise Exception('Address format error')
    return UInt160(data=data[1:21])


def hex_reverse(input):
    tmp_list = []
    for i in range(0, len(input), 2):
        tmp_list.append(input[i:i + 2])
    hex_str = "".join(list(reversed(tmp_list)))
    return hex_str


def int_to_hex(input):
    return binascii.hexlify(bytes([int(input)])).decode()


def create_multisign_contract(min_required,pubkeylist):
    verification_contract = Contract.CreateMultiSigContract(None, int(min_required), pubkeylist)
    return  verification_contract


def construct_opdata(address_from,address_to,value,contract_hash):
    op_data=""
    value=binascii.hexlify(BigInteger(value*pow(10,8)).ToByteArray()).decode()
    scripthash_from=ToScriptHash(address_from).ToString2()
    scripthash_to=ToScriptHash(address_to).ToString2()
    method=binascii.hexlify("transfer".encode()).decode()
    invoke_args=[value,scripthash_to,scripthash_from]
    for item in invoke_args:
        op_data+="".join([int_to_hex(len(item)/2),item])

    op_data+="53"     #PUSH3
    op_data+="c1"     #PACK
    op_data+=int_to_hex(len(method)/2)
    op_data+=method
    op_data+="67"                      #APPCALL
    op_data+=hex_reverse(contract_hash)
    op_data+= "f1"                      # maybe THROWIFNOT

    return op_data


def construct_txdata(op_data):
    tx_data=""
    contract_type="d1"
    version="01"
    scripthash_from=ToScriptHash(address_from).ToString2()
    timestamp = hex(int(time.time()))[2:]
    tx_data+=contract_type
    tx_data+=version
    tx_data+=int_to_hex(len(op_data)/2)
    tx_data+=op_data
    tx_data+="0000000000000000"
    tx_data+="02"       #attribute length
    tx_data+="20"       #AttributeType.Script
    tx_data+=scripthash_from
    tx_data+="f0"            #AttributeType.Remark
    tx_data+=int_to_hex(len(timestamp)/2)
    tx_data+=timestamp
    tx_data+="00"            #input length
    tx_data+="00"            #output length
    return tx_data


def construct_rawdata(tx_data):
    signstr1 =binascii.hexlify(Crypto.Sign(message=tx_data, private_key=private_key1)).decode()
    signstr2 =binascii.hexlify(Crypto.Sign(message=tx_data, private_key=private_key2)).decode()
    invoke_script=int_to_hex(len(signstr1)/2)+signstr1+int_to_hex(len(signstr2)/2)+signstr2
    verification_script=create_multisign_contract(2,[public_key1,public_key2])

    tx_data+="01"         #witness length
    tx_data+=int_to_hex(len(invoke_script)/2)
    tx_data+=invoke_script
    tx_data+=int_to_hex(len(verification_script.Script.decode())/2)
    tx_data+=verification_script.Script.decode()
    raw_data=tx_data
    return raw_data


def send_rawtransaction(raw_data):
    url = "http://192.168.138.128:10332"
    headers = {
        "Content-Type": "application/json"
    }

    data = {
        "jsonrpc": "2.0",
        "method": "sendrawtransaction",
        "params": [raw_data],
        "id": 1
    }
    res = requests.post(url, headers=headers, json=data).json()
    if res["result"]:
        return "sucess"
    return "fail"


def transfer_tnc(address_from,address_to,value,contract_hash):

    op_data=construct_opdata(address_from=address_from,address_to=address_to,value=value,contract_hash=contract_hash)

    tx_data=construct_txdata(op_data)

    raw_data=construct_rawdata(tx_data)
    reszult=send_rawtransaction(raw_data)
    return reszult



if __name__ == "__main__":

    contract_hash = "0c34a8fd0109df360c7cf7ca454404901db77f5e"

    private_key1 = "316eca27bcf72eb518cfde6cb7859afc6ebacd5992d921a061331625ce4ceb83"
    public_key1 = "02e6c97ef4151dc87756ee9dcf15f61591f9fd700c8ed98d8f009c53548bd62306"

    private_key2 = "eefc152a46960a4d3092146ae8b27890c3a3d12db14f6f7309d3f5c41b4e456d"
    public_key2 = "03eb0881d1d64754d50255bf16079ed6cbc3982463a8904cb919422b39178bef3f"

    address_to = "AdoHFZV8fxnVQBZ881mdGhynjGC3156Skv"
    address_from = "AW547uHKTHEdHCWdJ9RWqxZsbB5T8eyUmY"
    value = 3

    reszult=transfer_tnc(address_from=address_from,address_to=address_to,value=value,contract_hash=contract_hash)
    print (reszult)