import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class emitter:

    tweak=b""
    ck = b"" # full key aka the one who will cipher
    message = b"Hello"

    mac = b""

    X448_private_key = b""
    X448_public_key = b""
    X448_shared_key = b""

    data = b"my authenticated message"
    Ed448_private_key = b""
    Ed448_public_key = b""
    signature = b""

    def __init__(self):
        print("Message: ", self.message.decode())
        

    # ed448

    # assinatura é gerada a partir da mensagem, definida a partir da chave privada
    def generate_Ed448_signature(self):
        self.signature = self.Ed448_private_key.sign(self.data)
    
    # geracao da chave privada 
    def generate_Ed448_private_key(self):
        self.Ed448_private_key = Ed448PrivateKey.generate()
    
    # geracao da chave publica a partir da chave privada 
    def generate_Ed448_public_key(self):
        self.Ed448_public_key = self.Ed448_private_key.public_key()


    # x448

    # geracao da chave privada
    def generate_X448_private_key(self):
        # Generate a private key for use in the exchange.
        self.X448_private_key = X448PrivateKey.generate()
    
    # geracao da chave publica
    def generate_X448_public_key(self):
        self.X448_public_key = self.X448_private_key.public_key()

    # geracao da chave partilhada
    def generate_X448_shared_key(self, X448_receiver_public_key):
        key = self.X448_private_key.exchange(X448_receiver_public_key)
        
        self.X448_shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(key)

    def set_tweak(self, tweak):
        self.tweak = tweak

    

    def create_authentication(self, message):

        print("Authenticate message...")
        h = hmac.HMAC(self.ck, hashes.SHA256()) # full key aka the one who will cipher
        h.update(message)
        self.mac = h.finalize()


    def confirm_key_agreement(self):
        
        nonce = os.urandom(16)
        algorithm = algorithms.ChaCha20(self.X448_shared_key, nonce)
        cipher = Cipher(algorithm, mode=None)
        encryptor = cipher.encryptor()
        ct = encryptor.update(self.X448_shared_key)

        ct = nonce + ct

        return ct

    def create_ck(self): # full key aka the one who will cipher
        self.ck = self.X448_shared_key + self.tweak # full key aka the one who will cipher

    def encrypt_message(self):
        
        cipher_text = b''
        padder = padding.PKCS7(64).padder()
        padded_message = padder.update(self.message) + padder.finalize()

        
        # XOR METODO
        for x in range(0,len(padded_message),8):
            b=padded_message[x:x+8]
            for index, byte in enumerate(b):   
                cipher_text += bytes([byte ^ self.ck[x*8:(x+1)*8][index]]) # full key aka the one who will cipher

        print(cipher_text)

        self.create_authentication(cipher_text)

        complete_ct = self.mac + cipher_text 

        return complete_ct