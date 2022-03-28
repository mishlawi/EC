from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend



# basicamente o ED448

class receiver:

    X448_private_key = b""
    X448_public_key = b""
    X448_shared_key = b""
    
    tweak = b""
    ck = b""  # complete key aka the one who will cipher 

    assinatura = b"Signing Message"    

#acordo de chaves feito com “X448 key exchange” e “Ed448 Signing&Verification” para autenticação  dos agentes


    def check_Ed448_signature(self, signature, public_key):
        try:
            public_key.verify(signature, self.assinatura)
            print("Sucesso na autenticação ed448")
        except cryptography.exceptions.InvalidSignature:
            print("Erro na autenticação da assinatura ed448")


    # Generate a private key for use in the exchange.
    def privateKeyGenX448(self):
        self.X448_private_key = X448PrivateKey.generate()
    
    def publicKeyGenX448(self):
        self.X448_public_key = self.X448_private_key.public_key()

    def sharedKeyGenX448(self, X448_emitter_public_key):
        key = self.X448_private_key.exchange(X448_emitter_public_key)

        self.X448_shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake assinatura',
        ).derive(key)


    def create_ck(self):

        print("A criar a chave completa.")
        self.ck = self.X448_shared_key + self.tweak

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


    def verify_Auth(self, ck,message, signature):
        h = hmac.HMAC(ck, hashes.SHA256())
        h.update(message)
        try: 
            h.verify(signature)
            return True
        except:
            return False

    def decipher(self, ciphertext,receiver):
        
        complete_key = receiver.ck
        signature = ciphertext[32]
        ct = ciphertext[32:]

        if self.verify_Auth(complete_key, ct, signature):
            print("Autenticação do criptograma")
        else:
            print("Falha na autenticação do criptograma!")

        print("passou")
        clear_text = b''
            
        # XOR METODO
        for x in range (0,len(ct),8):
            b = ct[x:x+8]
            for index, byte in enumerate(b):   
                clear_text += bytes([byte ^ self.ck[x*8:(x+1)*8][index]])

        # Algoritmo para retirar padding para decifragem
        unpadder = padding.PKCS7(64).unpadder()

        # Retira bytes adicionados 
        unpadded_message = unpadder.update(clear_text) + unpadder.finalize()

        print(unpadded_message.decode("UTF-8"))

