import yaml
from funciones import Crypto_functions

def leer_y_extraer_mensajes_yaml(ruta_archivo):
    with open(ruta_archivo, 'r') as file:
        contenido_yaml = yaml.safe_load(file)  # Leer y cargar el archivo YAML

    llave = False
    # Iterar sobre los paquetes y extraer los datos
    for packet in contenido_yaml['packets']:
        datos_base64 = packet['data']  # Extraer el dato en base64
        if(llave == False):
            key = datos_base64
            llave = True
            continue

        # Extraer el nonce del mensaje
        nonce = datos_base64[:8]  # Asumimos que el nonce es de 8 bytes
        encrypted_message = datos_base64[8:]

        # Desencriptar el mensaje
        desencriptado = Crypto_functions.Salsa20_decrypt(key, nonce, encrypted_message)
        if(packet['peer'] == 1):
            print(f"Servidor: {desencriptado.decode('utf-8')}")
        else:
            print(f"Cliente: {desencriptado.decode('utf-8')}")
            
# Ruta del archivo YAML
ruta_archivo_yaml = 'data.yaml'  # Cambia esto con la ruta correcta

# Leer y extraer mensajes del archivo YAML
leer_y_extraer_mensajes_yaml(ruta_archivo_yaml)
