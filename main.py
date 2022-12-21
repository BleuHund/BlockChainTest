import base58
import json
import time


from Crypto.Hash import SHA3_256, SHA3_512, RIPEMD160
from Crypto.Signature import PKCS1_v1_5


from transaction import Transaction, TransactionMerkleTree
from wallet import Wallet


class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        self.index = index
        self.transactions = None
        if len(transactions) > 0:
            TransactionMerkleTree(transactions)
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce

    def __str__(self):
        return str(self.__dict__)

    def compute_hash(self):
        block_string = json.dumps(self, sort_keys=True, cls=Block.MyJsonEncoder)
        return SHA3_512.new(block_string.encode()).hexdigest()

    class MyJsonEncoder(json.JSONEncoder):
        def default(self, o):
            return o.__dict__


class Blockchain:
    def __init__(self, difficulty=3):
        self.unconfirmed_transactions = []
        self.chain = []
        self.create_genesis_block()
        self.difficulty = difficulty

    def __str__(self):
        return str([str(x) for x in self.chain])

    def create_genesis_block(self):
        genesis_block = Block(0, [], time.time(), "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)

    @property
    def last_block(self):
        return self.chain[-1]

    def proof_of_work(self, block):
        block.nonce = 0
        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * self.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()
        return computed_hash

    def is_valid_proof(self, block, block_hash):
        return (block_hash.startswith('0' * self.difficulty) and
                block_hash == block.compute_hash())

    def add_block(self, block, proof):
        previous_hash = self.last_block.hash
        if previous_hash != block.previous_hash:
            return False
        if not self.is_valid_proof(block, proof):
            return False
        block.hash = proof
        self.chain.append(block)
        return True

    def add_new_transaction(self, public_key, signed_transaction):
        try:
            Blockchain.validate_signature(public_key, signed_transaction)
        except AddressKeyMismatch:
            print("Wrong key")
        except ValueError:
            print("Invalid Signature")
        else:
            self.unconfirmed_transactions.append(signed_transaction)

    def mine(self):
        if not self.unconfirmed_transactions:
            return False
        last_block = self.last_block
        new_block = Block(index=last_block.index + 1,
                          transactions=self.unconfirmed_transactions,
                          timestamp=time.time(),
                          previous_hash=last_block.hash)
        proof = self.proof_of_work(new_block)
        self.add_block(new_block, proof)
        self.unconfirmed_transactions = []
        return new_block.index

    @staticmethod
    def validate_signature(public_key, signed_transaction):
        address = public_key
        h = RIPEMD160.new(SHA3_256.new(public_key.export_key()).hexdigest().encode())
        address = base58.b58encode(h.hexdigest()).decode("utf-8")
        if address != signed_transaction.transaction.sender:
            raise AddressKeyMismatch
        PKCS1_v1_5.new(public_key).verify(signed_transaction.transaction.compute_hash(), signed_transaction.signature)


class AddressKeyMismatch(Exception):
    pass


if __name__ == '__main__':
    wallet1 = Wallet()
    wallet2 = Wallet()

    wallet1.generate_new_wallet()
    wallet1.save_wallet()
    wallet2.generate_new_wallet()
    myBlockchain = Blockchain(difficulty=4)

    myTransaction01 = Transaction(wallet1.address, wallet2.address, 10.05)
    mySignedTransaction01 = myTransaction01.sign(wallet1.private_key)
    myBlockchain.add_new_transaction(wallet1.public_key, mySignedTransaction01)

    myTransaction02 = Transaction(wallet1.address, wallet2.address, 22.40)
    mySignedTransaction02 = myTransaction02.sign(wallet1.private_key)
    myBlockchain.add_new_transaction(wallet1.public_key, mySignedTransaction02)

    myTransaction03 = Transaction(wallet1.address, wallet2.address, 11.55)
    mySignedTransaction03 = myTransaction03.sign(wallet1.private_key)
    myBlockchain.add_new_transaction(wallet1.public_key, mySignedTransaction03)

    myTransaction04 = Transaction(wallet1.address, wallet2.address, 100.05)
    mySignedTransaction04 = myTransaction04.sign(wallet1.private_key)
    myBlockchain.add_new_transaction(wallet1.public_key, mySignedTransaction04)

    myBlockchain.mine()
    print(myBlockchain)
