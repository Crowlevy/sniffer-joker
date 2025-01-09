import os
from scapy.all import sniff, IP, TCP, UDP, ARP, DNS
from datetime import datetime

os.system('cls' if os.name == 'nt' else 'clear')

print("\033[1;32;40m" + "=" * 120)
print("███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗          ██╗ ██████╗ ██╗  ██╗███████╗██████╗")
print("██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗         ██║██╔═══██╗██║ ██╔╝██╔════╝██╔══██╗")
print("███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝         ██║██║   ██║█████╔╝ █████╗  ██████╔╝")
print("╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗    ██   ██║██║   ██║██╔═██╗ ██╔══╝  ██╔══██╗")
print("███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║    ╚█████╔╝╚██████╔╝██║  ██╗███████╗██║  ██║")
print("╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝     ╚════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝")
print("\033[1;32;40m" + "=" * 120)
print("\033[1;36;40m               Sniffer Joker - by Crowlevy")

print("\033[1;32;40m" + "=" * 120 + "\n")

def log_packet_broxa(packet):
    """
    log de pacotes para exibir todos os dados necessários, caso não dê é problema de execução no script,
    sendo provavelmente não ter sido executado como admin
    """
    print("\n" + "=" * 60)
    print(f"Hora de captura: {datetime.now()}")
    print(f"Resumo: {packet.summary()}")
    
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Protocolo: {packet[IP].proto}") #todos os processos de protocolo em larga de ip, aqui é onde será analisado uma maior gama de informações, dependendo do seu contexto de cabaço tbm
        print(f"IP de origem: {ip_src}")
        print(f"IP de destino: {ip_dst}")
        
        if TCP in packet:
            print("Protocolo de transporte: TCP")
            print(f"Porta de origem: {packet[TCP].sport}")
            print(f"Porta de destino: {packet[TCP].dport}")
            if packet[TCP].payload:
                print(f"Dados: {bytes(packet[TCP].payload).decode('utf-8', 'ignore')}")
        
        elif UDP in packet:
            print("Protocolo de transporte: UDP")
            print(f"Porta de origem: {packet[UDP].sport}")
            print(f"Porta de destino: {packet[UDP].dport}")
            if DNS in packet:
                print("Protocolo de aplicação: DNS")
                print(f"Requisição DNS para: {packet[DNS].qd.qname.decode('utf-8', 'ignore')}")
    
    elif ARP in packet:
        print("Protocolo: ARP")
        print(f"MAC de origem: {packet[ARP].hwsrc}")
        print(f"MAC de destino: {packet[ARP].hwdst}")
        print(f"IP de origem: {packet[ARP].psrc}")
        print(f"IP de destino: {packet[ARP].pdst}")
    
    print("=" * 60 + "\n")
    
def detect_open_ports(packet):
    """ detecta pacotes de TCP ou UDP com portas abertas """
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        if TCP in packet or UDP in packet:
            if TCP in packet:
                port = packet[TCP].dport
            else:
                port = packet[UDP].dport

            print(f"Detecção de porta aberta: {ip_src} -> {ip_dst} Porta: {port}")

def start_sniffer(filter_protocol=None):
    """
    aqui inicia o sniffer, ele filtra por protocolo, :param filter_protocol: Filtra os pacotes por protocolo 
    (ex.: 'tcp', 'udp', 'arp', 'dns')
    """
    print("\033[1;34m[INFO] Iniciando o Sniffer Joker...\033[0m")
    print("\033[1;32mPressione CTRL+C para parar a captura de protocolos\033[0m")
    try:
        sniff(filter=filter_protocol, prn=log_packet_broxa, store=False)
    except PermissionError:
        print("\033[1;31m[ERROR] Sua permissão foi negada. Execute o script como administrador/root.\033[0m")
    except KeyboardInterrupt:
        print("\n\033[1;31m Captura encerrada pelo usuário\033[0m")


if __name__ == "__main__":
    print("\033[1;33m=== Sniffer Joker ===\033[0m")
    print("1. Capturar todos os pacotes")
    print("2. Capturar pacotes TCP")
    print("3. Capturar pacotes UDP")
    print("4. Capturar pacotes DNS")
    print("5. Capturar pacotes ARP")
    print("6. Detectar portas abertas")
    choice = input("\nEscolha uma das opções: ")

    filter_option = None
    if choice == "2":
        filter_option = "tcp"
    elif choice == "3":
        filter_option = "udp"
    elif choice == "4":
        filter_option = "udp port 53"  # DNS usa UDP na porta 53
    elif choice == "5":
        filter_option = "arp"
    elif choice == "6":
        filter_option == None
        

    start_sniffer(filter_option)
