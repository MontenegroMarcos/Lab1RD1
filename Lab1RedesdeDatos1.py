import socket
import sys

def set_client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_address = ('127.0.0.1', 807)  # Cambia esta línea si el servidor tiene una IP diferente

    print('Connecting to %s port %s' % server_address, file=sys.stderr)

    sock.connect(server_address)

    try:
        message = 'Este es el mensaje que se enviara.'
        
        print('Sending "%s"' % message, file=sys.stderr)
        
        sock.sendall(message.encode())

        amount_received = 0
        amount_expected = len(message)

        while amount_received < amount_expected:
            data = sock.recv(16)
            amount_received += len(data)
            print('Received "%s"' % data.decode())

    finally:
        print('Closing socket', file=sys.stderr)
        sock.close()


def set_server(ip, port): #Seteamos el server

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #AF_INET es una constante que representa IPv4
    #SOCK_STREAM es una constante que representa el tipo de socket para una conexión TCP.

    server_ip = (ip, port)
    #La direccion IP dada por la letra

    sock.bind(server_ip) # bind() se utiliza para asociar el socket con la dirección del servidor.

    #La función listen() pone el socket en modo servidor, y accept() espera una conexión entrante.
    sock.listen(1)

    while True:
        print('Waiting for a connection...', file=sys.stderr)
        connection, client_ip = sock.accept()

        #Los datos se leen de la conexión con recv() y se transmiten con sendall().

        try:
            print('Connection from', client_ip, file=sys.stderr)
            # Recibe los datos en pequeños fragmentos y retransmítelos.
            while True:
                data = connection.recv(16)
                if not data:
                    print('No more data from', client_ip, file=sys.stderr)
                    break

                print('Received:', data.decode('utf-8'), file=sys.stderr)
                print('Sending data back to the client...', file=sys.stderr)
                connection.sendall(data)
            
        finally:
            # Cierra la conexion
            connection.close()

def analizar_archivo_pcap():
    # Carga el archivo de captura de Wireshark
    cap = pyshark.FileCapture("archivo.pcap")

    # Recorre los paquetes capturados y presenta la información relevante
    for packet in cap:
        print("Capa Física y Enlace:")
        print("Source MAC:", packet.eth.src)
        print("Destination MAC:", packet.eth.dst)
        print("Frame Length:", packet.length)

        print("Capa de Red:")
        print("Source IP:", packet.ip.src)
        print("Destination IP:", packet.ip.dst)

        print("Capa de Transporte:")
        print("Source Port:", packet[packet.transport_layer].srcport)
        print("Destination Port:", packet[packet.transport_layer].dstport)

        print("Capa de Aplicación:")
        if hasattr(packet, "http"):
            print("HTTP Method:", packet.http.request_method)
            print("HTTP URI:", packet.http.request_uri)
        elif hasattr(packet, "ftp"):
            print("FTP Command:", packet.ftp.command)

        print("=" * 40)

    # Cierra el archivo de captura
    cap.close()


if __name__ == "__main__":
    print("Setting client")
    set_client()