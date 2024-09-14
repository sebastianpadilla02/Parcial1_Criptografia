import socket
import threading

from funciones import Crypto_functions

key = None  # Define key as None

def manejar_cliente(client_socket):
    global key

    try:
        while True:
            # Recibir mensaje del cliente
            data = client_socket.recv(1024)
            if not data:
                break

            # Extraer el nonce del mensaje
            nonce = data[:8]  # Asumimos que el nonce es de 24 bytes
            encrypted_message = data[8:] # El mensaje encriptado (sin el nonce)

            # Desencriptar el mensaje
            desencriptar = Crypto_functions.Salsa20_decrypt(key, nonce, encrypted_message)
            print(f"Cliente: {desencriptar.decode('utf-8')}")
            
            # Enviar respuesta al cliente
            response = input("Servidor: ")

            # Generar un nuevo nonce para la respuesta
            nonce = Crypto_functions.generar_nonce()
            encriptar = Crypto_functions.Salsa20_encrypt(key, nonce, response.encode('utf-8'))

            # Enviar el nonce y el mensaje encriptado
            client_socket.send(nonce + encriptar)
    except Exception as e:
        print(f"Error en enviar_recibir_mensajes: {e}")
    finally:
        client_socket.close()

def iniciar_servidor():
    global key

    # Crear un socket para el servidor
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 8080))
    server_socket.listen(1)
    print("Esperando conexión...")

    # Aceptar la conexión del cliente
    client_socket, client_address = server_socket.accept()
    print(f"Conectado con {client_address}")

    # Generar clave y enviarla al cliente (la clave permanece constante)
    key = Crypto_functions.generar_clave_AES()
    client_socket.send(key)

    manejar_cliente(client_socket)
    server_socket.close()

if __name__ == "__main__":
    iniciar_servidor()