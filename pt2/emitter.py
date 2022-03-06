import os
import crypto
import cifra

class Emitter:
    def __init__(self, password, module):
        if module == 1:
            module_value = "crypto"
        else:
            module_value = "cifra"
        self.module = module_value
        self.key = None
        self.password = password
        self.key_salt = os.urandom(16)
 
    def derivate_key(self):
        # Parte 1
        if self.module == "crypto":
            key = crypto.derivate_key(self.password.encode('utf-8'), self.key_salt)
        # Parte 2
        elif self.module == "cifra":
            seed = cifra.derivate_key(self.password.encode('utf-8'), self.key_salt)
            key = cifra.prg(seed)
        self.key = key   
      
    def send_message(self, message):
        key_digest = crypto.authenticate_HMAC(self.key, self.key)
        # Parte 1
        if self.module == "crypto":
            aad = None # Retirou-se só para a comparação ser mais justa
            nonce, ct = crypto.encode(message.encode('utf-8'), aad, self.key)
        # Parte 2
        elif self.module == "cifra":
            nonce = b''
            ct = cifra.encode(self.key, message.encode("utf-8"))
        return key_digest + nonce + self.key_salt + ct