import socket
import threading

#importar el modulo funciones
from funciones import Crypto_functions

key = None  # Define key as None

def recibir_mensajes(client_socket):
    global key
    try:
        # Recibir la clave del servidor
        key = client_socket.recv(1024)
        if not key:
            print("No se recibió la clave.")
            return

        while True:
            # Recibir el mensaje del servidor
            data = client_socket.recv(1024)
            if not data:
                break

            # Extraer el nonce del mensaje
            nonce = data[:8]  # Asumimos que el nonce es de 24 bytes
            encrypted_message = data[8:]

            # Desencriptar el mensaje
            desencriptado = Crypto_functions.Salsa20_decrypt(key, nonce, encrypted_message)
            print(f"Servidor: {desencriptado.decode('utf-8')}")

    except Exception as e:
        print(f"Error en recibir_mensajes: {e}")
    finally:
        client_socket.close()

def iniciar_cliente():
    global key  # Hacer referencia a la variable global key
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 8080))

    # Hilo para recibir mensajes del servidor
    thread = threading.Thread(target=recibir_mensajes, args=(client_socket,))
    thread.start()

    while True:
        # Verificar que se haya recibido la clave antes de enviar un mensaje
        if key is None:
            print("Esperando la clave del servidor...")
            continue

        # Enviar mensaje al servidor
        try:
            message = input("Cliente: ")
            if message.lower() == 'salir':
                print("Cerrando conexión...")
                client_socket.close()
                break

            # Generar un nuevo nonce para el mensaje
            nonce = Crypto_functions.generar_nonce()

            # Encriptar el mensaje
            encriptar = Crypto_functions.Salsa20_encrypt(key, nonce, message.encode('utf-8'))

            # Enviar el nonce y el mensaje encriptado
            client_socket.send(nonce + encriptar)
        except Exception as e:
            print(f"Error al enviar mensaje: {e}")
            client_socket.close()
            break

if __name__ == "__main__":
    iniciar_cliente()