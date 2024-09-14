## Descripción del programa
Se implementa en Python el cifrado y descifrado de mensajes de tipo texto que se intercambian entre un servidor y un cliente. Para el proceso criptografico se hace uso de dos cifradores: Salsa20 y AES-256


## Librerias o paquetes necesarios

### Pycryptodome
Encargado de las funciones de encriptado y desencriptado para Salsa20 y AES-256
```
pip install pycryptodome
```

### Pyyaml
Usada por el atacante para poder leer el archivo generado por Wireshark en formato YAML, dado una ruta.

```
pip install pyyaml
```