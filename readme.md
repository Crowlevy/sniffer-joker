# Sniffer Joker 🤡
### Projeto feito no foda-se, tá aí                                                              

## Descrição
O **Sniffer Joker** se baseia na captura de pacotes de rede (sniffer), foi desenvolvida em Python e permite monitorar o tráfego de redes de forma otimizada, fiz ele visando uma melhora em casos para dar suporte técnico no meu servidor. Quem quiser aprender diagnóstico de rede e **pentesting** ético (ou não ético), recomendo demais.

**⚠️ AVISO LEGAL:** Este programa deve ser utilizado apenas em redes onde você possui autorização explícita para monitorar. O uso indevido pode ser ilegal e é de responsabilidade única do usuário. (Faz no sigilo que tá tudo certo)
---

## Funcionalidades
- Monitoramento de pacotes em tempo real
- Filtros de protocolo (TCP, UDP, HTTP, etc.)
- Registros detalhados de cada pacote capturado
- Captura de cabeçalhos e payloads para análise
- Logs organizados para facilitar a visualização
---

## Instalação e Uso
### **Pré-requisitos**
1. Python 3.8 ou superior.
2. Biblioteca `scapy`.
3. Npcap (para usuários Windows).

### **Instalando Dependência**
Execute esse comando para instalar a dependência necessária:
```bash
pip install scapy
```

## **Executando o Sniffer**
```bash
git clone https://github.com/crowlevy/sniffer-joker.git
cd sniffer-joker
python sniffer_joker.py
```
### Insira o _**protocolo**_ desejado para captura (exemplo: tcp, udp, http, ou deixe vazio para capturar tudo).

## **Demonstração no terminal**
```bash
Pacote capturado:
- Origem: 192.168.1.5
- Destino: 192.168.1.10
- Protocolo: TCP
```

## Caso tenha algum bug, por favor me reportar ou fazer ou fork para melhorias