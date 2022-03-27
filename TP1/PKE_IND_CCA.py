class PKE_IND_CCA(object):
    
    def __init__(self, N, timeout=None):
        
        # N é o tamanho usado para os primos p e q no RSA
        self.kem = KEM_RSA(N)
    
    
    # XOR de 2 arrays de bytes byte-a-byte! A mensagem(data) deve ser menor ou igual á chave(mask)! Caso contrario, a chave
    # ou mask é 'repetida' para os bytes seguintes dos dados
    def xor(self, data, mask):
        
        masked = b''
        ldata = len(data)
        lmask = len(mask)
        i = 0
        while i < ldata:
            for j in range(lmask):
                if i < ldata:
                    masked += (data[i] ^^ mask[j]).to_bytes(1, byteorder='big')
                    i += 1
                else:
                    break
                    
        return masked
    
    
    # Funcao usada para cifrar que recebe a mensagem e uma chave publica (e,n)
    def cifra(self, m, e, n):
        
        # Gerar um inteiro aleatorio r entre 0 < r < n
        r = self.kem.h(n)
        # Calculo do g(r), em que g é uma função de hash (no nosso caso, sha-256)
        g = hashlib.sha256(str(r).encode()).digest()
        # Efetuar o calculo de: y ← x⊕ g(r)
        y = self.xor(m, g)
        yi = Integer('0x' + hashlib.sha256(y).hexdigest())
        # Gerar o salt para derivar a chave
        salt = os.urandom(16)
        # Calcular (k,w) ← f(y || r)
        (k,w) = self.kem.f(str(yi + r).encode(), e, n, salt)
        # Calcular c ← k⊕ r
        c = self.xor(str(r).encode(), k)
        
        return (y,w,c)
    
    
    # Funcao usada para decifrar que recebe o criptograma, o 'encapsulamento' da chave, a tag e o vetor inicializacao
    def decifra(self, y, w, c):
        
        # Fazer o desencapsulamento da chave
        k = self.kem.desencapsula(w)
        # Calcula r <- c  ⊕  k
        r = self.xor(c, k)
        # Buscar os 16 primeiros bytes de w para obter o salt
        salt = w[:16]
        yi = Integer('0x' + hashlib.sha256(y).hexdigest())
        # Verificar se (w,k) ≠ f(y∥r)
        if (k,w) != self.kem.f(str(yi + int(r)).encode(), self.kem.e, self.kem.n, salt):
            # Lancar excecao
            raise IOError
        else:
            # Calculo do g(r), em que g é uma função de hash (no nosso caso, sha-256)
            g = hashlib.sha256(r).digest()
            # Calcular m <- y⊕ g(r)
            m = self.xor(y, g)
        
        return m