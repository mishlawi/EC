from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class receiver:

    X448_private_key = b""
    X448_public_key = b""
    X448_shared_key = b""
    
    tweakable = b""
    complete_key = b""

    signing_message = b"Signing Message"


    def check_Ed448_signature(self, signature, public_key):
        
        if public_key.verify(signature, self.signing_message):
            print("Sucesso na autenticação ed448")
        else:
            print("Erro na autenticação da assinatura ed448")




    def generate_X448_private_key(self):
        # Generate a private key for use in the exchange.
        self.X448_private_key = X448PrivateKey.generate()
    
    def generate_X448_public_key(self):
        self.X448_public_key = self.X448_private_key.public_key()

    def generate_X448_shared_key(self, X448_emitter_public_key):
        key = self.X448_private_key.exchange(X448_emitter_public_key)

        self.X448_shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(key)


    def set_tweak(self, tweak):
        self.tweakable = tweak


    def create_complete_key(self):

        print("Create the complete key...")
        self.complete_key = self.X448_shared_key + self.tweakable

    def confirm_key_agreement(self, ct):
        
        nonce = ct[:16]
        key = ct[16:]

        algorithm = algorithms.ChaCha20(self.X448_shared_key, nonce)
        cipher = Cipher(algorithm, mode=None)

        decryptor = cipher.decryptor()
        d_key = decryptor.update(key)

        if d_key == self.X448_shared_key:
            print("Chaves correspondem. CONFIRMAÇÃO DA CHAVE ACORDADA")
        else:
            print("Erro na verificacao da correspondencia entre chaves")

        return




    def decrypt_message(self, ciphertext):

        mac = ciphertext[32]
        ct = ciphertext[32:]

        try:
            h = hmac.HMAC(self.complete_key, hashes.SHA256(), backend=default_backend())
            h.update(ct)
            h.verify(mac)
            print("Autenticação da mensagem com sucesso")
        except:
            print("Autenticação da mensagem sem sucesso")
            return


        clear_text = b''
            
        # XOR METODO
        for x in range (0,len(ct),8):
            b = ct[x:x+8]
            for index, byte in enumerate(b):   
                clear_text += bytes([byte ^ self.complete_key[x*8:(x+1)*8][index]])

        # Algoritmo para retirar padding para decifragem
        unpadder = padding.PKCS7(64).unpadder()

        # Retira bytes adicionados 
        unpadded_message = unpadder.update(clear_text) + unpadder.finalize()

        print(unpadded_message.decode("UTF-8"))


    #def create_tweakable(self, nonce):
        
    #    print("Create tweakable block cipher...")
        
    #    key_l = self.X448_shared_key[0:32]
    #    key_f = self.X448_shared_key[32:]
    #    algorithm = algorithms.ChaCha20(key_l, nonce)
    #    cipher = Cipher(algorithm, mode=None)
    #    ct = cipher.encryptor()
    #    self.tweakable = ct.update(b"Tweakable")
    #    return
