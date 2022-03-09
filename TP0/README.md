# Trabalho Prático 0

## Use a package Criptography  para 

1. Criar um comunicação privada assíncrona entre um agente Emitter e um agente Receiver que cubra os seguintes aspectos:
	* Autenticação do criptograma e dos metadados (associated data). Usar uma cifra simétrica  num modo HMAC  que seja seguro contra ataques aos “nounces” .
	* Os “nounces” são gerados por um gerador pseudo aleatório (PRG) construído por um função de hash em modo XOF.
	* O par de chaves **cipher key**, **mackey** , para cifra e autenticação, é acordado entre agentes usando o protocolo DH com autenticação dos agentes usando assinaturas DSA.

2. Criar uma cifra com autenticação de meta-dados a partir de um PRG
	* Criar um gerador pseudo-aleatório do tipo XOF (“extended output function”) usando o SHAKE256, para gerar uma sequência de palavras de 64 bits. 
	* O gerador deve poder gerar até um limite de 2^N palavras (n é  um parâmetro) armazenados em long integers do Python.
	* A “seed” do gerador funciona como cipher\_key e é gerado por um KDF a partir de uma “password” .
	* A autenticação do criptograma e dos dados associados é feita usando o próprio SHAKE256.

3. Compare experimentalmente a eficiência dos dois esquemas de cifra.

	
