import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import * 
import sys

def mainMenu():
    print('''\nSelecciona una opción:
    1. Analizar paquetes de un protocolo en específico
    2. Analizar todos los paquetes de cualquier protocolo
    3. Salir
    ''')
    return

def inputNombreInterfaz():
    
    nombreInterfaz = input('Ingrese el nombre de la interfaz de red: ')
    choice = input('La red "{}" será analizada '.format(nombreInterfaz))
    return nombreInterfaz
    


def numValido(message):
    while True:
        try:
            val = int(input(message))
            if val <= 0:
                print('Formato incorrecto, el número debe ser positivo')
            else:
                return val
        except ValueError:
            print('No es una opción válida\n')


def resumenProtocolPacket(interface, numPaquete, protocolo):
    try:
        a = sniff(filter = protocolo, count = numPaquete, iface = nombreInterfaz, prn = lambda x: x.summary())
        print(a)
        return
    except:
        sys.exit('Ha ocurrido un error. Comprueba que el protocolo es compatible con tu interfaz de red.\n')

def infoProtocolPacket(interface, numPaquete, protocolo):
    try:
        a = sniff(filter = protocolo, count = numPaquete, iface = nombreInterfaz, prn = lambda x: x.show())
        print(a)
        return
    except:
        sys.exit('No fue encontrada la interfaz, asegurate de haber escrito el nombre correctamente.\n')

def resumenPacket(interface, numPaquete):
    try:
        a = sniff(count = numPaquete, iface = nombreInterfaz, prn = lambda x: x.summary())
        print(a)
        return
    except:
        sys.exit('No fue encontrada la interfaz, asegurate de haber escrito el nombre correctamente.\n')

def infoPacket(interface, numPaquete):
    try:
        a = sniff(count = numPaquete, iface = nombreInterfaz, prn = lambda x: x.show())
        print(a)
        return
    except:
        sys.exit('No fue encontrada la interfaz, asegurate de haber escrito el nombre correctamente.\n')


def protocolPackets():
    while True:
        print('''\nProtocolos aceptados:
        Ethernet (ether)
        Wireless LAN (wlan)
        Internet protocolo (ip)
        IPv6 (ip6)
        Address Resolution Protocol (arp)
        Reverse ARP (rarp)
        Transmission Control Protocol (tcp)
        User Datagram Protocol (udp)
        Internet Control Message Protocol (icmp)
        ''')

        protocolo = input('Ingresa el protocolo que desees filtrar: ')

        if protocolo not in {'ether', 'wlan', 'ip', 'ip6', 'arp', 'rarp', 'tcp', 'udp', 'icmp'}:
            print('Protocolo inválido\n')
            continue
        else:
            choice = input('\nQuieres ver toda la información de cada paquete?  (Y/N): ')
            
            if choice in {'Y'}:
                choice = input('\nSe analizarán 50 paquetes, quieres cambiar ese número? (Y/N): ')
                if choice in {'Y'}:
                    numPaquete = numValido('Ingresa el número de paquetes que quieres analizar:: ')
                    infoProtocolPacket(nombreInterfaz, numPaquete, protocolo)
                else:
                    numPaquete = 50
                    infoProtocolPacket(nombreInterfaz, numPaquete, protocolo)
                break
            
            elif choice in {'N'}:
                choice = input('\nSe analizarán 50 paquetes, quieres cambiar ese número? (Y/N): ')
                if choice in {'Y'}:
                    numPaquete = numValido('Ingresa el número de paquetes que quieres analizar: ')
                    resumenProtocolPacket(nombreInterfaz, numPaquete, protocolo)
                else:
                    numPaquete = 50
                    resumenProtocolPacket(nombreInterfaz, numPaquete, protocolo)
                break
            
            else:
                print('Invalid option\n')

def analizarPaquetes():
    while True:
        choice = input('\nQuieres ver toda la información de cada paquete? (Y/N): ')
        
        if choice in {'Y'}:
            choice = input('\nSe analizarán 50 paquetes, quieres cambiar ese número? (Y/N): ')
            if choice in {'Y'}:
                numPaquete = numValido('Ingresa el número de paquetes que quieres analizar: ')
                infoPacket(nombreInterfaz, numPaquete)
            else:
                numPaquete = 50
                infoPacket(nombreInterfaz, numPaquete)
            break
        
        elif choice in {'N'}:
            choice = input('\nSe analizarán 50 paquetes, quieres cambiar ese número? (Y/N): ')
            if choice in {'Y'}:
                numPaquete = numValido('Ingresa el número de paquetes que quieres analizar:')
                resumenPacket(nombreInterfaz, numPaquete)
            else:
                numPaquete = 50
                resumenPacket(nombreInterfaz, numPaquete)
            break
        
        else:
            print('Opción no válida\n')



def loopMenu():
    
    while True:
        
        mainMenu()

        choice = int(input('Escoge una opción: '))
        
        if choice == 1:
            protocolPackets()
          
        
        elif choice == 2:
            analizarPaquetes()

        
        elif choice == 3:
            
            sys.exit()

        else:
            print('No es una opción válida \n')


if __name__ == '__main__':
    
    print('---Sniffer De Red---\n')
        
    nombreInterfaz = inputNombreInterfaz()
    
    loopMenu()