from emitter import emitter
from receiver import receiver 
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms



# 1. Use o “package” Cryptography para
#     1. Implementar uma AEAD com “Tweakable Block Ciphers” 
#      A cifra por blocos primitiva, usada para gerar a “tweakable block cipher”, é o AES-256 ou o ChaCha20.
#     2. Use esta construção para construir um canal privado de informação assíncrona com acordo de chaves feito com “X448 key exchange” e “Ed448 Signing&Verification” para autenticação  dos agentes. Deve incluir uma fase de confirmação da chave acordada.



# tweakable block cipher é um parâmetro que permite ser associado à chave e fará parte do processo de cifragem
#Ou seja, temos de criar uma chave, um tweakable e juntar os dois e encriptar as cenas




#AEAD terá de ser construído por nós e é do tipo E&M

#AEAD do tipo E&M
def create_tweakable(key):

    
    nounce = os.urandom(16)
    algorithm = algorithms.ChaCha20(key, nounce)
    cipher = Cipher(algorithm, mode=None)
    ct = cipher.encryptor()
    tweak = ct.update(b"Tweakable")
    return tweak




emitter = emitter()
receiver = receiver()



#Autenticação dos agentes
print("Setup do ED448 (Autenticação dos agentes)")
emitter.generate_Ed448_private_key()
emitter.generate_Ed448_signature()
emitter.generate_Ed448_public_key()

receiver.check_Ed448_signature(emitter.signature, emitter.Ed448_public_key)



#Setup do Key exchange (X448)
print("Setup do X448 (Key Exchange)")
emitter.generate_X448_private_key()
receiver.generate_X448_private_key()

emitter.generate_X448_public_key()
receiver.generate_X448_public_key()

emitter.generate_X448_shared_key(receiver.X448_public_key)
receiver.generate_X448_shared_key(emitter.X448_public_key)


# Verificação de se as chaves foram bem acordadas
key_ciphertext = emitter.confirm_key_agreement()
receiver.confirm_key_agreement(key_ciphertext)


tweak = create_tweakable(emitter.X448_shared_key)
emitter.set_tweak(tweak)
receiver.set_tweak(tweak)


emitter.create_complete_key()
receiver.create_complete_key()

ciphertext = emitter.encrypt_message()
receiver.decrypt_message(ciphertext)


