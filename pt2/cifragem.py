"""
2. Criar uma cifra com autenticação de meta-dados a partir de um PRG
    1. Criar um gerador pseudo-aleatório do tipo XOF (“extened output function”)
     usando o SHAKE256, para gerar uma sequência de palavras de 64 bits. 
        1. O gerador deve poder gerar até um limite de $$\,2^n\,$$ palavras ($$n$$ é  um parâmetro) armazenados em long integers do Python.
        2. A “seed” do gerador funciona como $$\mathtt{cipher\_key}$$ e é gerado por um KDF a partir de uma “password” .
        3. A autenticação do criptograma e dos dados associados é feita usando o próprio SHAKE256.
    b. Defina os algoritmos de cifrar e decifrar : para cifrar/decifrar uma mensagem com blocos de 64 bits, os “outputs” do gerador são usados como máscaras XOR dos blocos da mensagem. 
    Essencialmente a cifra básica é uma implementação do  “One Time Pad”.
"""
from email import message
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

# Basically deriving a key from a specific password
def derive_key(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000)

    return kdf.derive(password) # returns the key derived from the password


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
        x.append(message[i:i+BLOCK])
    return x

def cipher(k,msg):
    ciphertext = b''
    pad = padding.PKCS7(64).padder()
    
    # adds padding to the last block of bytes of the message -> this garantees that the block size is multiple
    # basically stuffs the last block with pad chars 
    padded = pad.update(message) + pad.finalize()
    # mesage is divided in blocks of 8 bytes
    p = pad_divide(padded)

    for x in range (len(p)): # Percorre blocos do texto limpo
        for bloco, byte in enumerate(p[x]): # Percorre bytes do bloco do texto limpo
            ciphertext += bytes([byte ^ k[x:(x+1)*BLOCK][bloco]]) 
    return ciphertext


def decipher(k,ciphertext):
    plaintext=b''
    
    p=pad_divide(ciphertext)

    for x in range (len(p)): # Percorre blocos do texto cifrado
        for bloco, byte in enumerate(p[x]): # Percorre bytes do bloco do texto cifrado
            plaintext += bytes([byte ^ k[x:(x+1)*BLOCK_SIZE][bloco]]) 
    
    # Algoritmo para retirar padding para decifragem
    unpadder = padding.PKCS7(64).unpadder()
    # Retira bytes adicionados 
    unpadded = unpadder.update(plaintext) + unpadder.finalize()
    return unpadded.decode("utf-8")
    