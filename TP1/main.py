import os
from emitter import emitter
from receiver import receiver 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


# 1. Use o “package” Cryptography para
#     1. Implementar uma AEAD com “Tweakable Block Ciphers” 
#      A cifra por blocos primitiva, usada para gerar a “tweakable block cipher”, é o AES-256 ou o ChaCha20.
#     2. Use esta construção para construir um canal privado de informação assíncrona com acordo de chaves feito com “X448 key exchange” e “Ed448 Signing&Verification” para autenticação  dos agentes. Deve incluir uma fase de confirmação da chave acordada.



# Parâmetro que permite ser associado à chave e fará parte do processo de cifragem ->  tweakable block cipher
# Ou seja, temos de criar uma chave, um tweakable e juntar os dois e encriptar as cenas


#AEAD terá de ser construído por nós e é do tipo E&M

#AEAD do tipo E&M


def create_tweakable(key):
    
    nounce = os.urandom(16)
    algorithm = algorithms.ChaCha20(key, nounce)
    cipher = Cipher(algorithm, mode=None)
    ct = cipher.encryptor()
    tweak = ct.update(b"Tweakable")
    return tweak

#Agent Auth 
#1

def ed448_setup(emitter):
    emitter.ed448privateKeygen()
    emitter.ed448signatureGen()
    emitter.ed448publicKeygen()
    print("setup do ED448 no emmiter")
    print("\n\n\n\n")

#Setup do Key exchange (X448)
# 2
def x448keys(emitter,receiver):
    emitter.privateKeyGenX448()
    receiver.privateKeyGenX448()
    # chaves privadas geradas 1o porque as publicas sao geradas a partir delas
    print("chaves privadas geradas no receiver e no emitter")
    emitter.publicKeyGenX448()
    receiver.publicKeyGenX448()
    print("chaves publicas geradas no receiver e no emitter")
    print("\n\n\n\n")
#3
def sharedkeygen(emitter,receiver):
    
    emitter.sharedKeyGenX448(receiver.X448_public_key)
    print("chave partilhada do emiter criada")
    receiver.sharedKeyGenX448(emitter.X448_public_key)
    print("chave partilhada do receiver criada")


emitter = emitter()
emitter.message=b"Hello12"
receiver = receiver()
ed448_setup(emitter)
receiver.check_Ed448_signature(emitter.signature, emitter.Ed448_public_key)
x448keys(emitter,receiver)
sharedkeygen(emitter,receiver)
# Verificação de se as chaves foram bem acordadas
key_ciphertext = emitter.confirm_key_agreement()
receiver.confirm_key_agreement(key_ciphertext)


tweak = create_tweakable(emitter.X448_shared_key)
emitter.tweak = tweak
receiver.tweak = tweak


emitter.create_ck()
receiver.create_ck()

ciphertext = emitter.cipher()
print("Texto cifrado: ", ciphertext)
receiver.decipher(ciphertext,receiver)


