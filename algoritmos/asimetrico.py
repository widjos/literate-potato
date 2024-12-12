from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import  hashes

# Generacion de las llaves RSA
llave_privada = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

#Generacion de LLave publica.
llave_publica = llave_privada.public_key()

# Mi mensaje original que encriptare
mensaje = b"Hola , este es mi mensaje para encriptar!"

# Encriptacion de mi mnensaje con mi llave publica.
texto_cifrado = llave_publica.encrypt(
    mensaje,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print(f"Texto Encriptado: \n{texto_cifrado} \n")

# Desencriptacion de mi mensaje con la llave privada.
mensaje_desencriptado = llave_privada.decrypt(
    texto_cifrado,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print(f"Mensaje Desencriptado: {mensaje_desencriptado.decode()} \n")