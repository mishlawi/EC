"""
2. Criar uma cifra com autenticação de meta-dados a partir de um PRG
    1. Criar um gerador pseudo-aleatório do tipo XOF (“extened output function”) usando o SHAKE256, para gerar uma sequência de palavras de 64 bits. 
        1. O gerador deve poder gerar até um limite de $$\,2^n\,$$ palavras ($$n$$ é  um parâmetro) armazenados em long integers do Python.
        2. A “seed” do gerador funciona como $$\mathtt{cipher\_key}$$ e é gerado por um KDF a partir de uma “password” .
        3. A autenticação do criptograma e dos dados associados é feita usando o próprio SHAKE256.
    b. Defina os algoritmos de cifrar e decifrar : para cifrar/decifrar uma mensagem com blocos de 64 bits, os “outputs” do gerador são usados como máscaras XOR dos blocos da mensagem. 
    Essencialmente a cifra básica é uma implementação do  “One Time Pad”.
"""
