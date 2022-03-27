
#
#   2. Use o SageMath para, 
#    1. Construir uma classe Python que implemente um KEM- RSA. A classe deve
#        1. Inicializar cada instância recebendo  o parâmetro de segurança (tamanho em bits do módulo RSA) e gere as chaves pública e privada.
#        2. Conter funções para encapsulamento e revelação da chave gerada.
#    2. Construir,  a partir deste KEM e usando a transformação de Fujisaki-Okamoto, um PKE que seja IND-CCA seguro.

import math
import os, hashlib


# defined in
# https://doc.sagemath.org/html/en/thematic_tutorials/numtheory_rsa.html

class KEM_RSA(object):

    def __init__(self,sec_par):
        
        # Mersenne numbers 
        # If p is prime and Mp=2p−1 is also prime,
        #  then Mp is called a Mersenne prime
        
        self.q = math.random_prime(pow(2,sec_par-1),pow(2,sec_par)-1)
        self.p = math.random_prime(pow(2,sec_par+1-1),pow(2,sec_par+1)-1)
        self.n = self.q * self.p

        # φ(n)=(p−1)(q−1)
        # phi serve para calcular o expoente da chave publica
        self.phi = (self.p-1)*(self.q-1)

        self.e = ZZ.random_element(self.phi)
        while gcd(e, self.phi) != 1:
            e = ZZ.random_element(self.phi)
        
        # Para calcular d, usamos o 'extended Euclidean algorithm': de−k⋅φ(n)=1 -> Assim, so precisamos de descobrir d e -k
        # xgcd(x, y) retorna um triplo (g, s, t) que satisfaz a identidade de Bézout: g=gcd(x,y)=sx+ty 
        self.bezout = xgcd(self.e, self.phi)
        
        

        # d = mod(s,φ(n)), uma vez que 1 < d < φ(n)
        s = self.bezout[1]
        self.d = Integer(mod(s, self.phi))





    # recebe os parametros da chave publica
    # gera uma chave simétrica com a sua respetiva encapsulacao

    def encapsula(self, e, n):
        
        # gera-se um inteiro aleatório 
        r = ZZ.random_element(n)
        
        # Gerar o salt para a derivacao da chave a ser usado no KDF
        salt = os.urandom(16)

        # parâmetro de encapsulamento da chave
        # Criptograma com este inteiro usado para o encapsulamento da chave\ (c ← seed^e mod n)
        key_encapsulation = Integer(power_mod(r, e, n))

        # geracao da chave simetrica
        w = hashlib.pbkdf2_hmac('sha256', str(r).encode(), salt, 100000)

        # chave simetrica com encapsulamento
        k = (w,salt + str(key_encapsulation).encode())       

        return k    
    
    # Funcao usada para revelar uma chave, a partir do seu "encapsulamento"
    # recebe o encapsulamento com o salt
    def revelacao(self, cs):
        
        # Buscar os 16 primeiros bytes para obter o salt e o restante é o "encapsulamento" da chave
        salt = cs[:16]
        c = int(cs[16:].decode())
        
        # Obter o r (r ← c^d mod n) com o algoritmo power_mod
        r = Integer(power_mod(c, self.d, self.n))
        
        # Geracao da chave simetrica a partir do r (W ← KDF(r))
        w = hashlib.pbkdf2_hmac('sha256', str(r).encode(), salt, 100000)
        
        return w




# Parametro de seguranca
N = 1024

# Chave publica: (n,e)
# Chave privada: (p,q,d)
# Inicializacao da classe responsavel por implementar o KEM-RSA
kemrsa = KEM_RSA(N)

# Verificar que ed == 1 (mod φ(n))
#print(mod(kemrsa.e * kemrsa.d, kemrsa.phi))

# Procede-se ao encapsulamento
(w,c) = kemrsa.encapsula(kemrsa.e, kemrsa.n)

print("Chave devolvida pelo encapsulamento: ")
print(w)
print("\n'Encapsulamento' da chave: ")
print(c)

# Procede-se ao desencapsulamento
w1 = kemrsa.revelacao(c)
print("\nChave devolvida pelo desencapsulamento: ")
print(w1)

# Verificar se a chave devolvida pelo desencapsulamento é igual à que foi gerada no encapsulamento
if w == w1:
    print("As chaves são iguais!!!")
else:
    print("As chaves são diferentes!!!")

