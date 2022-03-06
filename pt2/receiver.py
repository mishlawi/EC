import crypto
import cifra

KEY_DIGEST_LEN = 32 # Bytes
NONCE_LEN = 12 # Bytes
SALT_LEN = 16 # Bytes

class Receiver:
    def __init__(self, password,module):
        if module == 1:
            module_value = "crypto"
        elif module == 2:
            module_value = "cifra"
        self.module = module_value
        self.key = None
        self.password = password
    