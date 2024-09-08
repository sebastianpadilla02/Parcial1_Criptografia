import socket
import threading

from funciones import functions

# Definir la variable global `key`
key = None

def recibir_mensajes(client_socket):
    global key 
    try:
        # Recibir la llave del servidor
        key = client_socket.recv(1024)
        if not key:
            print("No se recibió la clave.")
            return

        while True:
            message = client_socket.recv(1024)
            if not message:
                break
            desencriptado = functions.AES_ECB_decrypt(key, message)
            print(f"Servidor: {desencriptado.decode('utf-8')}")

    except Exception as e:
        print(f"Error en recibir_mensajes: {e}")
    finally:
        client_socket.close()

def iniciar_cliente():
    global key  # Hacer referencia a la variable global `key`
    
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

            encriptar = functions.AES_ECB_encrypt(key, message.encode('utf-8'))
            client_socket.send(encriptar)
        except Exception as e:
            print(f"Error al enviar mensaje: {e}")
            client_socket.close()
            break

if __name__ == "__main__":
    iniciar_cliente()
