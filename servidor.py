import socket
import threading

from funciones import Crypto_functions

key = None  # Define key as None

def manejar_cliente(client_socket):
    global key
    while True:
        # Recibir mensaje del cliente
        message = client_socket.recv(1024)
        if not message:
            break
        desencriptar = Crypto_functions.AES_ECB_decrypt(key, message)
        print(f"Cliente: {desencriptar.decode('utf-8')}")
        
        # Enviar respuesta al cliente
        response = input("Servidor: ")
        encriptar = Crypto_functions.AES_ECB_encrypt(key, response.encode('utf-8'))
        client_socket.send(encriptar)

    client_socket.close()

def iniciar_servidor():
    global key

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 8080))
    server_socket.listen(1)
    print("Esperando conexión...")

    client_socket, client_address = server_socket.accept()
    print(f"Conectado con {client_address}")

    # Generar clave y enviarla al cliente
    key = Crypto_functions.generar_clave_AES()
    client_socket.send(key)

    manejar_cliente(client_socket)
    server_socket.close()

if __name__ == "__main__":
    iniciar_servidor()
