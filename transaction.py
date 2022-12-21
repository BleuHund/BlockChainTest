import binascii
import json
import math

from Crypto.Hash import SHA3_512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


class Transaction:
    def __init__(self, sender: bytes, receiver: bytes, value):
        self.sender = sender.decode("utf-8")
        self.receiver = receiver.decode("utf-8")
        self.value = value

    def compute_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return SHA3_512.new(block_string.encode())

    def sign(self, private_key: RSA.RsaKey):
        return SignedTransaction(self, binascii.hexlify(
            PKCS1_v1_5.new(private_key).sign(self.compute_hash())
        ).decode("utf-8"))


class SignedTransaction:
    def __init__(self, transaction: Transaction, signature: str):
        self.transaction = transaction
        self.signature = signature


class TransactionMerkleTree:
    def __init__(self, signed_transactions: [SignedTransaction]):

        depth = math.ceil(math.log2(len(signed_transactions)))
        number_leaves = 2 ** depth

        last_layer = []
        # Hash all the transactions
        for signed_transaction in signed_transactions:
            last_layer.append(TransactionMerkleTree.Node(node_hash=signed_transaction.transaction.compute_hash(),
                                                         signed_transaction=signed_transaction))
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
                    f"{last_layer[j * 2].node_hash}{last_layer[j * 2 + 1].node_hash}".encode())
                this_layer.append(TransactionMerkleTree.Node(
                    node_hash=node_hash, right_child=last_layer[j * 2], left_child=last_layer[j * 2 + 1]))
            last_layer = this_layer
            this_layer = []

        self.root = last_layer[0]

    class Node:
        def __init__(self, node_hash: SHA3_512.SHA3_512_Hash, signed_transaction: SignedTransaction=None,
                     right_child=None, left_child=None):
            self.node_hash = node_hash
            self.signed_transaction = signed_transaction
            self.right_child = right_child
            self.left_child = left_child

        def __str__(self):
            return str(self.node_hash)