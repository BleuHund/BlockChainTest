import base58
import hashlib
import json
import math
import time

from hashlib import sha3_512, sha3_256

from Crypto.PublicKey import RSA


class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce

    def __str__(self):
        return str(self.__dict__)

    def compute_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha3_512(block_string.encode()).hexdigest()


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

    def add_new_transaction(self, transaction):
        self.unconfirmed_transactions.append(transaction)

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


class Transaction:
    def __init__(self, sender, receiver, value):
        self.sender = sender
        self.receiver = receiver
        self.value = value

    def compute_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha3_512(block_string.encode()).hexdigest()


class TransactionMerkleTree:
    def __init__(self, transactions):

        depth = math.ceil(math.log2(len(transactions)))
        number_leaves = 2 ** depth

        last_layer = []
        # Hash all the transactions
        for transaction in transactions:
            last_layer.append(TransactionMerkleTree.Node(node_hash=transaction.compute_hash()))
        # Buffer the tree so it's complete and full
        if len(transactions) % 2 == 0:
            for i in range(number_leaves - len(last_layer)):
                last_layer.append(last_layer[-2])
        else:
            for i in range(number_leaves - len(last_layer)):
                last_layer.append(last_layer[-1])

        this_layer = []
        for i in range(depth):
            for j in range(len(last_layer)//2):
                node_hash = sha3_512(f"{last_layer[j*2].node_hash}{last_layer[j*2+1].node_hash}".encode()).hexdigest()
                this_layer.append(TransactionMerkleTree.Node(node_hash, last_layer[j*2], last_layer[j*2+1]))
            last_layer = this_layer
            this_layer = []

        self.root = last_layer[0]

    class Node:
        def __init__(self, node_hash=None, right_child=None, left_child=None):
            self.node_hash = node_hash
            self.right_child = right_child
            self.left_child = left_child

        def __str__(self):
            return str(self.node_hash)


class Wallet:
    def __init__(self):
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.public_key().export_key()
        self.address = self.public_key
        h = hashlib.new('ripemd160')
        h.update(sha3_256(self.public_key).hexdigest().encode())
        self.address = base58.b58encode(h.hexdigest())


if __name__ == '__main__':
    print(Wallet().address)
    print(Wallet().address)
    print(Wallet().address)
    transactions = [Transaction(x, x, x) for x in range(5)]
    TransactionMerkleTree(transactions)
    # myBlockchain = Blockchain(difficulty=4)
    # print(myBlockchain)
    # myBlockchain.add_new_transaction(-15.0)
    # myBlockchain.mine()
    # myBlockchain.add_new_transaction(-20.0)
    # myBlockchain.mine()
    # print(myBlockchain)
