from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
import random
import os


# Cryptographic key derivation
#
# Deriving a key suitable for use as input to an encryption algorithm. 
# Typically this means taking a password and running it through an algorithm such as PBKDF2HMAC or HKDF.
# This process is typically known as key stretching.
#
BLOCK = 8 

# Basically deriving a key from a specific password - kdf

def derive_key(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        )

    return kdf.derive(password) # returns the key derived from the password aka cipher_key


# generates char sequence to be used to cipher the data
def prg(seed,N):
    digest = hashes.Hash(hashes.SHAKE256(8 * pow(2,N))) # sequencia palavras 64 bits / 8 = 8 bytes
    digest.update(seed)
    msg = digest.finalize()
    return msg

# generate 2^N msg words

def pad_divide(message):
    x = []
    for i in range (0,len(message), BLOCK):
        next = i+BLOCK
        x.append(message[i:next])
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


def decipher(k,ciphertext):
    plaintext=b''
    
    p=pad_divide(ciphertext)

    for x in range (len(p)): # Percorre blocos do texto cifrado
        for bloco, byte in enumerate(p[x]): # Percorre bytes do bloco do texto cifrado
            plaintext += bytes([byte ^ k[x:(x+1)*BLOCK][bloco]]) 
    
    # Algoritmo para retirar padding para decifragem
    unpadder = padding.PKCS7(64).unpadder()
    # Retira bytes adicionados 
    unpadded = unpadder.update(plaintext) + unpadder.finalize()
    return unpadded.decode("utf-8")
    
cipher_key = derive_key(b'password')
msg = prg(cipher_key,2)
mensagem = b"Ultra secret message"

ct = cipher(msg,mensagem)
dt = decipher(msg,ct)


print("OG TEXT: ", mensagem)
print("CT:  ", ct)
print("DT:  ", dt)