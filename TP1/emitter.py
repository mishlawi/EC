import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

BLOCK = 8

class emitter:

    # ATTRIBUTES

    tweak=b"" # the tweak
    message = b"" # the message
    mac = b""

    X448_private_key = b""
    X448_public_key = b""
    X448_shared_key = b""

    assinatura = b"Signing Message" # assinatura
    Ed448_private_key = b""
    Ed448_public_key = b""
    signature = b"" # the encoded signature after mixing it up with the public key


    ck = b"" # full key aka the one who will cipher


    # assinatura é gerada a partir da mensagem, definida a partir da chave privada
    def ed448signatureGen(self):
        self.signature = self.Ed448_private_key.sign(self.assinatura)
    
    # geracao da chave privada 
    def ed448privateKeygen(self):
        self.Ed448_private_key = Ed448PrivateKey.generate()
    
    # geracao da chave publica a partir da chave privada 
    def ed448publicKeygen(self):
        self.Ed448_public_key = self.Ed448_private_key.public_key()


    # x448

    # geracao da chave privada
    def privateKeyGenX448(self):
        # Generate a private key for use in the exchange.
        self.X448_private_key = X448PrivateKey.generate()
    
    # geracao da chave publica do emitter
    def publicKeyGenX448(self):
        self.X448_public_key = self.X448_private_key.public_key()

    # geracao da chave partilhada a partir da derivaçao da chave publica do outro peer
    def sharedKeyGenX448(self, peerPublickey): # esta public key é referente ao outro peer da comunicacao
        key = self.X448_private_key.exchange(peerPublickey)
        
        self.X448_shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake assinatura',
        ).derive(key)


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


    def pad_divide(self,message):
        x = []
        for i in range (0,len(message), BLOCK):
            x.append(message[i:i+BLOCK])
        return x


    def cipher(self):
        ciphertext = b''

        padder = padding.PKCS7(64).padder()
        padded = padder.update(self.message) + padder.finalize()

        p = self.pad_divide(padded)
        for x in range (len(p)): # Percorre blocos do texto limpo
            for bloco, byte in enumerate(p[x]): # Percorre bytes do bloco do texto limpo
                ciphertext += bytes([byte ^ self.ck[x:(x+1)*BLOCK][bloco]]) # xor of 2 bit sequences plain text and cipher_key

        print(ciphertext)
        
        
        h = hmac.HMAC(self.ck, hashes.SHA256()) # full key aka the one who will cipher
        h.update(ciphertext)
        self.mac = h.finalize()
        

        complete_ct = self.mac + ciphertext 

        return complete_ct




"""
    def create_authentication(self, message):

        h = hmac.HMAC(self.ck, hashes.SHA256()) # full key aka the one who will cipher
        h.update(message)
        self.mac = h.finalize()

        return
"""
