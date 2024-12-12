import jwt
import hashlib
import base64
import secrets
import time
import json

# Llave secreta para encriptar y desencriptar.
LLAVE_SECRETA = secrets.token_urlsafe(16)

# Creamos un diccionario con los datos de nuestro usuario
data_usuario = {"usuario": "sergio", "email": "sergio@ejemplo.com"}

# Codificamos nuestro diccionario a un valor json 
user_data_json = json.dumps(data_usuario)

# Calculamos el valor hash SHA-256  para la informacion del usuario.
hash_object = hashlib.sha256(user_data_json.encode())
hash_hex = hash_object.hexdigest()

# Codificamos nuestro ash enbase64
hash_base64 = base64.b64encode(hash_hex.encode()).decode()

# Creamos nuestro encabezado de JWT.
header = {"typ": "JWT", "alg": "HS256"}

# Creamos nuestro cargador de informacion
payload = {"sub": data_usuario["usuario"], "exp": int(time.time()) + 3600, "iat": int(time.time())}

# Creamos un metodo de validacion del cargador con nuestra ionformacion para generar nuestro token.
token = jwt.encode(payload, LLAVE_SECRETA, algorithm="HS256", headers=header)

print(f" Nuestro token sera:   {token} \n")

#Decoficamos nuestro token para ver el resultado encriptado en nuestra cadena  hash
resultado = jwt.decode(token, LLAVE_SECRETA, algorithms=["HS256"])

print(f"Informacion :   {resultado} \n")