from emitter import Emitter
from receiver import Receiver
from cryptography.hazmat.primitives.asymmetric import dh
import time


def main():
    parameters = dh.generate_parameters(generator=2, key_size=1024)
    # Cria instâncias dos agentes
    emmiter = Emitter(parameters)
    receiver = Receiver(parameters)
    
    # Deriva chaves
    emmiter.derivate_key(receiver.get_public_key())
    receiver.derivate_key(emmiter.get_public_key())
    
    start = time.time_ns()
    # Emmiter envia dados: mensagem + assinatura
    dados = emmiter.send_message("Segredo que não se pode partilhar")
    print('encrypted text:',dados)
    
    try:
        # Receiver decifra mensagem
        pt = receiver.read_message(dados)
        stop = time.time_ns()
        print('decrypted text:', pt)
        print('elapsed time:', (stop-start), 'ns')
    except:
        # Falha na autenticação da chave
        print("Falha na autenticação da chave")  
    

if __name__ == "__main__":
    main()