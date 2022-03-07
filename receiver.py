import os
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Receiver:
    def __init__(self,parameters):
      self.dh_parameters = parameters
      self.private_key = None
      self.derived_key = None
    
    def get_public_key(self):
        self.private_key = self.dh_parameters.generate_private_key()
        return self.private_key.public_key()

    def derivate_key(self,emmiter_public):
        shared_key = self.private_key.exchange(emmiter_public)
        
        self.derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)

        return self.derived_key
    
    def unpack_data(self, dados):
      signature = dados[0:32]
      nonce = dados[32:32+16]
      ct = dados[32+16:]

      return signature, nonce, ct

    def verify(self,signature):
      h = hmac.HMAC(self.derived_key, hashes.SHA256())
      h.update(b'this is a message to check the signature')
      return h.verify(signature)
      

    def read_message(self, ct):
      signature, nonce, ct = self.unpack_data(ct)
      try :
          # verifica se o digest gerado acima é igual ao digest recebido como parâmetro
          self.verify(signature)
      except:
          raise Exception("Falha na autenticidade da chave") 

      aesgcm = AESGCM(self.derived_key)
      texto_limpo = aesgcm.decrypt(nonce, ct, b'some associated data')
    
      return texto_limpo.decode('utf-8')
  



