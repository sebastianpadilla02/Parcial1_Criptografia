from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import Salsa20

class Crypto_functions:
    # Clave de 16 bytes (128 bits), 24 bytes (192 bits) o 32 bytes (256 bits)
    def generar_clave_AES():
        clave = get_random_bytes(32)
        return clave

    def generar_iv_AES():
        iv = get_random_bytes(16)
        return iv

    def generar_nonce():
        nonce = get_random_bytes(8)
        return nonce

    def AES_ECB_encrypt(key, texto_original):
        cipher = AES.new(key, AES.MODE_ECB)
        texto_padded = pad(texto_original, AES.block_size)
        texto_encriptado = cipher.encrypt(texto_padded)
        return texto_encriptado

    def AES_ECB_decrypt(key, texto_encriptado):
        cipher = AES.new(key, AES.MODE_ECB)
        texto_desencriptado = cipher.decrypt(texto_encriptado)
        texto_desencriptado = unpad(texto_desencriptado, AES.block_size)
        return texto_desencriptado

    def AES_CBC_encrypt(key, iv, texto_original):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        texto_padded = pad(texto_original, AES.block_size)
        texto_encriptado = cipher.encrypt(texto_padded)
        return texto_encriptado

    def AES_CBC_decrypt(key, iv, texto_encriptado):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        texto_desencriptado = cipher.decrypt(texto_encriptado)
        texto_desencriptado = unpad(texto_desencriptado, AES.block_size)
        return texto_desencriptado

    def AES_CTR_encrypt(key, iv, texto_original):
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
        texto_encriptado = cipher.encrypt(texto_original)
        return texto_encriptado

    def AES_CTR_decrypt(key, iv, texto_encriptado):
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
        texto_desencriptado = cipher.decrypt(texto_encriptado)
        return texto_desencriptado

    def ChaCha20_encrypt(key, iv, texto_original):
        cipher = ChaCha20.new(key=key, nonce=iv)
        texto_encriptado = cipher.encrypt(texto_original)
        return texto_encriptado

    def ChaCha20_decrypt(key, iv, texto_encriptado):
        cipher = ChaCha20.new(key=key, nonce=iv)
        texto_desencriptado = cipher.decrypt(texto_encriptado)
        return texto_desencriptado

    def Salsa20_encrypt(key, iv, texto_original):
        cipher = Salsa20.new(key=key, nonce=iv)
        texto_encriptado = cipher.encrypt(texto_original)
        return texto_encriptado

    def Salsa20_decrypt(key, iv, texto_encriptado):
        cipher = Salsa20.new(key=key, nonce=iv)
        texto_desencriptado = cipher.decrypt(texto_encriptado)
        return texto_desencriptado

