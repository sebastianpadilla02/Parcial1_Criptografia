import socket
import threading

from funciones import Crypto_functions

key = None  # Define key as None

# Función para manejar al cliente
def manejar_cliente(client_socket):
    global key

    try:
        while True:
            # Recibir mensaje del cliente
            data = client_socket.recv(1024)
            if not data:
                break

            # Extraer el nonce(iv) del mensaje
            iv = data[:16]  # Asumimos que el nonce(iv) es de 16 bytes en AES-256
            encrypted_message = data[16:] # El mensaje encriptado

            # Desencriptar el mensaje
            desencriptar = Crypto_functions.AES_CBC_decrypt(key, iv, encrypted_message)
            # Imprimir el mensaje del cliente
            print(f"Cliente: {desencriptar.decode('utf-8')}")
            
            # Enviar respuesta al cliente
            response = input("Servidor: ")

            # Generar un nuevo nonce(iv) para la respuesta
            iv = Crypto_functions.generar_iv_AES()
            # Encriptar la respuesta
            encriptar = Crypto_functions.AES_CBC_encrypt(key, iv, response.encode('utf-8'))

            # Enviar el iv y el mensaje encriptado
            client_socket.send(iv + encriptar)
    except Exception as e:
        print(f"Error en enviar_recibir_mensajes: {e}")
    finally:
        client_socket.close()

def iniciar_servidor():
    global key

    # Generar clave y enviarla al cliente (la clave permanece constante)
    key = Crypto_functions.generar_clave_AES()

    # Guardar la clave en un archivo binario
    with open('key.bin', 'wb') as file:
        file.write(key)

    # Crear un socket para el servidor
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 8080))
    server_socket.listen(1)
    print("Esperando conexión...")

    # Aceptar la conexión del cliente
    client_socket, client_address = server_socket.accept()
    print(f"Conectado con {client_address}")

    manejar_cliente(client_socket)
    server_socket.close()

if __name__ == "__main__":
    iniciar_servidor()