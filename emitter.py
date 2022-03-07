import os
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Emitter:
    def __init__(self,parameters):
        self.dh_parameters = parameters
        self.private_key = None
        self.derived_key = None
      
    def derivate_key(self,receiver_public):
        self.private_key = self.dh_parameters.generate_private_key()
        shared_key = self.private_key.exchange(receiver_public)
        
        self.derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)

        return self.derived_key
    
    def get_public_key(self):
        return self.private_key.public_key()

    #assinatura (aka DSA)
    def auth(self,message):
        h = hmac.HMAC(self.derived_key, hashes.SHA256())
        h.update(message)
        return h.finalize()

    def send_message(self, message):
        signature = self.auth(b'this is a message to check the signature')
        message = message.encode('utf-8')
        nonce = os.urandom(16)
        aesgcm = AESGCM(self.derived_key)
        ct = aesgcm.encrypt(nonce, message, b'some associated data')

        return signature + nonce + ct




  
      