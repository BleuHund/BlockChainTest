import base58
import binascii
import json
import math
import time

from Crypto.Hash import SHA3_256, SHA3_512, RIPEMD160
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


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


class Transaction:
    def __init__(self, sender, receiver, value):
        self.sender = sender.decode("utf-8")
        self.receiver = receiver.decode("utf-8")
        self.value = value

    def compute_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return SHA3_512.new(block_string.encode())

    def sign(self, private_key):
        return SignedTransaction(self, binascii.hexlify(
            PKCS1_v1_5.new(private_key).sign(self.compute_hash())
        ).decode("utf-8"))


class SignedTransaction:
    def __init__(self, transaction, signature):
        self.transaction = transaction
        self.signature = signature


class TransactionMerkleTree:
    def __init__(self, signed_transactions):

        depth = math.ceil(math.log2(len(signed_transactions)))
        number_leaves = 2 ** depth

        last_layer = []
        # Hash all the transactions
        for signed_transaction in signed_transactions:
            last_layer.append(TransactionMerkleTree.Node(node_hash=signed_transaction.transaction.compute_hash(), signed_transaction=signed_transaction))
        # Buffer the tree so it's complete and full
        if len(signed_transactions) % 2 == 0:
            for i in range(number_leaves - len(last_layer)):
                last_layer.append(last_layer[-2])
        else:
            for i in range(number_leaves - len(last_layer)):
                last_layer.append(last_layer[-1])

        this_layer = []
        for i in range(depth):
            for j in range(len(last_layer) // 2):
                node_hash = SHA3_512.new(
                    f"{last_layer[j * 2].node_hash}{last_layer[j * 2 + 1].node_hash}".encode()).hexdigest()
                this_layer.append(TransactionMerkleTree.Node(node_hash=node_hash, right_child=last_layer[j * 2], left_child=last_layer[j * 2 + 1]))
            last_layer = this_layer
            this_layer = []

        self.root = last_layer[0]

    class Node:
        def __init__(self, node_hash=None, signed_transaction=None, right_child=None, left_child=None):
            self.node_hash = node_hash
            self.signed_transaction = signed_transaction
            self.right_child = right_child
            self.left_child = left_child

        def __str__(self):
            return str(self.node_hash)


class Wallet:
    def __init__(self):
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.public_key()
        self.address = self.public_key
        h = RIPEMD160.new(SHA3_256.new(self.public_key.export_key()).hexdigest().encode())
        self.address = base58.b58encode(h.hexdigest())


if __name__ == '__main__':
    wallet1 = Wallet()
    wallet2 = Wallet()
    myBlockchain = Blockchain(difficulty=4)

    myTransaction = Transaction(wallet1.address, wallet2.address, 10.05)
    mySignedTransaction01 = myTransaction.sign(wallet1.private_key)
    myBlockchain.add_new_transaction(wallet1.public_key, mySignedTransaction01)
    myBlockchain.mine()
    print(myBlockchain)
