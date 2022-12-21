import base58
import os

from Crypto.Hash import SHA3_256, RIPEMD160
from Crypto.PublicKey import RSA


class Wallet:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.address = None
        self.is_valid_wallet = False

    def generate_new_wallet(self):
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.public_key()
        self.address = self.public_key
        h = RIPEMD160.new(SHA3_256.new(self.public_key.export_key()).hexdigest().encode())
        self.address = base58.b58encode(h.hexdigest())
        self.is_valid_wallet = True

    def save_wallet(self, folder=os.environ['HOME']+"/.ssh/", key_name="blockchain_wallet.pem"):
        with open(folder+key_name, 'wb') as f:
            f.write(self.private_key.export_key('PEM'))

    def load_wallet(self, folder=os.environ['HOME']+"/.ssh/", key_name="blockchain_wallet.pem"):
        with open(folder+key_name) as f:
            self.private_key = RSA.import_key(f.read())
            self.public_key = self.private_key.public_key()
            self.address = self.public_key
            h = RIPEMD160.new(SHA3_256.new(self.public_key.export_key()).hexdigest().encode())
            self.address = base58.b58encode(h.hexdigest())
            self.is_valid_wallet = True
