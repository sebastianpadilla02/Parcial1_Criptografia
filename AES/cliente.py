import socket
import threading
from funciones import Crypto_functions

key = None  # Definir la clave como None inicialmente

#Función para leer la clave desde un archivo
def leer_clave_desde_archivo(file_path):
    try:
        with open(file_path, 'rb') as file:
            return file.read()  # Leer la clave en formato binario
    except Exception as e:
        print(f"Error al leer el archivo de clave: {e}")
        return None

#Función para recibir mensajes del servidor
def recibir_mensajes(client_socket):
    global key
    try:
        while True:
            # Recibir el mensaje del servidor
            data = client_socket.recv(1024)

            # Espera de mensaje del servidor
            if not data:
                break

            # Extraer el nonce(iv) del mensaje
            iv = data[:16]  # Asumimos que el nonce(iv) es de 16 bytes (para AES)
            encrypted_message = data[16:] # El mensaje encriptado

            # Desencriptar el mensaje
            desencriptado = Crypto_functions.AES_CBC_decrypt(key, iv, encrypted_message)

            # Limpiar la línea de entrada del cliente para evitar interferencias, e imprimir el mensaje del servidor
            print(f"\nServidor: {desencriptado.decode('utf-8')}\nCliente: ", end='', flush=True)
    except Exception as e:
        print(f"Error en recibir_mensajes: {e}")
    finally:
        # Cerrar el socket del cliente
        client_socket.close()

def iniciar_cliente():
    global key  # Hacer referencia a la variable global `key`
    
    # Leer la clave desde un archivo
    archivo_clave = 'key.bin'
    key = leer_clave_desde_archivo(archivo_clave)
    
    if key is None:
        print("No se pudo cargar la clave desde el archivo. Cerrando cliente.")
        return

    # Crear un socket para el cliente
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('192.168.230.34', 8080)) # Conectar al servidor, necesario cambiar la IP para pruebas en diferentes equipos

    # Hilo para recibir mensajes del servidor
    thread = threading.Thread(target=recibir_mensajes, args=(client_socket,))
    thread.daemon = True  # Hilo en segundo plano para no bloquear
    thread.start()

    while True:
        # Verificar que se haya cargado la clave antes de enviar un mensaje
        if key is None:
            print("Esperando la clave...")
            continue

        # Enviar mensaje al servidor
        try:
            # Leer el mensaje ingresado por el cliente
            message = input("Cliente: ")
            if message.lower() == 'salir':
                print("Cerrando conexión...")
                client_socket.close()
                break

            # Generar un nuevo nonce (IV) para el mensaje
            iv = Crypto_functions.generar_iv_AES()

            # Encriptar el mensaje
            encriptar = Crypto_functions.AES_CBC_encrypt(key, iv, message.encode('utf-8'))

            # Enviar el nonce y el mensaje encriptado
            client_socket.send(iv + encriptar)
        except Exception as e:
            print(f"Error al enviar mensaje: {e}")
            client_socket.close()
            break

if __name__ == "__main__":
    iniciar_cliente()
