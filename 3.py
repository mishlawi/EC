from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import time


BLOCK = 8 



def derive_key(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        )

    return kdf.derive(password) # returns the key derived from the password aka cipher_key


def cifraGCM(key,plaintext, nonce):
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, plaintext, b'some associated data')
    
def prg(seed,N):
    digest = hashes.Hash(hashes.SHAKE256(8 * pow(2,N))) # sequencia palavras 64 bits / 8 = 8 bytes
    digest.update(seed)
    msg = digest.finalize()
    return msg


def pad_divide(message):
    x = []
    for i in range (0,len(message), BLOCK):
        x.append(message[i:i+BLOCK])
    return x


def cipher(k,msg):
    ciphertext = b''
    pad = padding.PKCS7(64).padder()
    
    # adds padding to the last block of bytes of the message -> this garantees that the block size is multiple
    # basically stuffs the last block with pad chars 
    padded = pad.update(msg) + pad.finalize()
    # mesage is divided in blocks of 8 bytes
    p = pad_divide(padded)

    for x in range (len(p)): # Percorre blocos do texto limpo
        for bloco, byte in enumerate(p[x]): # Percorre bytes do bloco do texto limpo
            ciphertext += bytes([byte ^ k[x:(x+1)*BLOCK][bloco]]) # xor of 2 bit sequences plain text and cipher_key
    return ciphertext

N = 10  # Vamos ter sequencias de 1024 bytes


def snd_cipher():
    pwd = b"password"
    key = derive_key(pwd)
    plaintext = os.urandom(2 ** N)
    words = prg(key,N)
    ciphertext = cipher(plaintext,words)
    
def fst_cipher():
    pwd = b"password"
    key = derive_key(pwd)
    nonce = os.urandom(16)
    plaintext = os.urandom(2 ** N)
    ciphertext = cifraGCM(key, plaintext, nonce)


start = time.time_ns()
fst_cipher()
stop = time.time_ns()
print('elapsed time fst:', stop-start, 'ns')

start = time.time_ns()
snd_cipher()
stop = time.time_ns()
print('elapsed time snd:', stop-start, 'ns')
