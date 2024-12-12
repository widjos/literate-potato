from cryptography.fernet import Fernet

# Generacion de la llave para decifrar
llave = Fernet.generate_key()
cifrador = Fernet(llave)

# Mensaje original que quiero cifrar.
mensaje = b"Hola esta es una prueba para un mensaje con cifrado simetrico!"

# Encriptacion de mensaje con el cifrado que utiliza  la llave.
texto_cifrado = cifrador.encrypt(mensaje)
print(f"Texto Cifrado: {texto_cifrado} \n")

# Desencriptacion del codigo.
mensaje_desencriptado = cifrador.decrypt(texto_cifrado)
print(f"Mensaje desencriptado: {mensaje_desencriptado.decode()}\n")