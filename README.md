# literate-potato
Algoritmos para encriptacion ejemplos. Utilizando python ya que es un lenguaje con esa versatilidad para crear scripts.

- [literate-potato](#literate-potato)
  - [Cifrado  Simetrico](#cifrado--simetrico)
  - [Librerias utilizadas](#librerias-utilizadas)
- [Cifrado  Asimetrico](#cifrado--asimetrico)
- [Cifrado  Hash](#cifrado--hash)

## Cifrado  Simetrico
---

En este cifrado se utilizan  una unica llave para la encriptacion y descencriptacion por lo cual es la misma clave la cual se utiliza por el que envia el mensaje y por el que lo recibe. Este crifrado tiene como ventaja la eficiencia para encriptar grandes cantidades de datos. 

Librerias utilizadas
------

```cryptography.fernet``` es una biblioteca de Python que proporciona una implementación de la symmetric encryption (cifrado simétrico) utilizando el algoritmo Fernet. Fernet es un algoritmo de cifrado simétrico que utiliza un secreto compartido para cifrar y descifrar datos.

Este cifrado consta de tres etapas principales: 

1. __Generacion de la LLave:__ 
   
   En esta etapa  el se genera una llave secreta para encriptar nuestro mensaje: 

```python
# Generacion de la llave para decifrar
    llave = Fernet.generate_key()
    cifrador = Fernet(llave)

# Mensaje original que quiero cifrar tambien describimos nuestro mensaje a encriptar.
    mensaje = b"Hola esta es una prueba para un mensaje con cifrado simetrico!"


```

2. __Encriptacion__:
   
   En esta etapa nosotros encriptaremos nuestor mensaje utiliznado la libreria con nuestra llave. 

```python

# Encriptacion de mensaje con el cifrado que utiliza  la llave y luego hacemos un print para nuestro resultado.
    texto_cifrado = cifrador.encrypt(mensaje)
    print(f"Texto Cifrado: {texto_cifrado}")

```

3. __Desencriptacion:__
   Esta es la ultima etapa donde desencriptamos nuestro mensaje utilizando la misma llave. 

```python
# Desencriptacion del codigo utiliando el metodo decruypt de nuestra libreraia y por ultimo realizamos un print del resutlado.
    mensaje_desencriptado = cifrador.decrypt(texto_cifrado)
    print(f"Mensaje desencriptado: {mensaje_desencriptado.decode()}")

```

 Cifrado  Asimetrico
===
---

Este cifrado tambien es conocido como cifrado publico , su principal caracteristica es utilizar un par de llaves una publica y una privada para descifrar el mensaje. Este es un metodo seguro que permite compartir con todos la llave publica pero la llave privada solo la tiene el que necesita descencriptar. 

Librerias utlizadas 

- `cryptography`: `cryptography` es una biblioteca que proporciona recetas y primitivas criptográficas a los desarrolladores de Python. Su objetivo es ser una herramienta sólida y confiable para operaciones relacionadas con la criptografía en Python.

- `hazmat`: Dentro de la biblioteca `cryptography`, `hazmat` es un submódulo que contiene implementaciones de bajo nivel de algoritmos criptográficos y primitivas que no están destinadas para el uso directo de la mayoría de los desarrolladores. El código en este módulo se considera "materiales peligrosos" y se debe manejar con cuidado.

- `cryptography.hazmat.backends.default_backend`: Esta es una función que devuelve el backend criptográfico predeterminado para el sistema. El backend criptográfico es responsable de proporcionar las implementaciones reales de operaciones criptográficas utilizando bibliotecas específicas de la plataforma como OpenSSL.

- `cryptography.hazmat.primitives.asymmetric.rsa`: Este módulo proporciona una implementación del algoritmo de cifrado asimétrico RSA (Rivest-Shamir-Adleman). Permite la generación de claves, cifrado, descifrado y operaciones de firma utilizando claves RSA.

- `cryptography.hazmat.primitives.asymmetric.padding`: Este módulo proporciona clases para esquemas de relleno que se pueden usar con algoritmos de cifrado asimétrico. Los esquemas de relleno se utilizan para garantizar que los datos a cifrar o firmar cumplan con los requisitos del algoritmo criptográfico subyacente.

Los pasos a utilizar para este ejemplo seran: 

1. __Generacion de Par de llaves:__ Se genera una llave publica  y una llave privada. 
   
```python

# Generacion de las llaves RSA
llave_privada = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
#Generacion de llave publica con la llave privada encriptada.
llave_publica = llave_privada.public_key()
```

2. __Encriptacion:__ El que envia el mensaje encripta el mensaje con la llave publica del que recibe. 

 ```python

 # Mi mensaje original que encriptare
mensaje = b"Hola , este es mi mensaje para encriptar!"

# Encriptacion de mi mensaje con mi llave publica utilianzao el algoritmo SHA246.
texto_cifrado = llave_publica.encrypt(
    mensaje,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(f"Texto Encriptado: \n{texto_cifrado} \n")
 ```  

3. __Desencriptacion:__ El que recibe el mensaje desencripta con su llave privada. 

```python
# Desencriptacion de mi mensaje con la llave privada.
mensaje_desencriptado = llave_privada.decrypt(
    texto_cifrado,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
#Imprimir el menssaje ya desencriptado
print(f"Mensaje Desencriptado: {mensaje_desencriptado.decode()} \n")
```


 Cifrado  Hash
===
---
En este caso utilizaremos un ejemplo con SHA256 para generer un JSON WEB TOKEN JWT. 

El algoritmo SHA-256 se utiliza porque:

- Genera un resultado de tamaño fijo (256 bits)
- Es determinístico, siempre produce el mismo - resultado para los mismos datos
- Es criptográficamente seguro, imposible revertir el proceso de hashing
- Es ampliamente compatible con sistemas y lenguajes de programación

Estas características lo hacen ideal para aplicaciones que requieren proteger la seguridad de los datos, como autenticación, autorización y verificación de integridad.

Para este ejemplo utilizaremos las sigueintes librerias : 


- ```jwt```: biblioteca oficial de Python para manejar tokens JSON Web Token (JWT).
- ```hashlib```: biblioteca para realizar hashing de cadenas, útil para crear firmas digitales y verificar integridad de datos.
- ```base64```: biblioteca para trabajar con codificación base64, utilizada para codificar y decodificar los tokens JWT.
- ```secrets```: biblioteca para generar claves y valores aleatorios seguros, útil para generar claves de seguridad.
- ```time```: biblioteca para trabajar con fechas y horas, útil para establecer expiraciones de tokens.
- ```json```: biblioteca para trabajar con objetos JSON, utilizada para serializar y deserializar los tokens JWT.

Para esta encriptacion la dividimos entres partes.

1. __Generacion LLave Secreta__ : Se genera la llave secreta. 

```python
# Llave secreta para encriptar y desencriptar.
LLAVE_SECRETA = secrets.token_urlsafe(16)
```

2. __Creacion del Hash y Base64__: Se genera nuestro objeto hash con nustro objeto y lo convertimos a base64.
```python
# Creamos un diccionario con los datos de nuestro usuario
data_usuario = {"usuario": "sergio", "email": "sergio@ejemplo.com"}

# Codificamos nuestro diccionario a un valor json 
user_data_json = json.dumps(data_usuario)

# Calculamos el valor hash SHA-256  para la informacion del usuario.
hash_object = hashlib.sha256(user_data_json.encode())
hash_hex = hash_object.hexdigest()

# Codificamos nuestro ash enbase64
hash_base64 = base64.b64encode(hash_hex.encode()).decode()

```
3.  __Genereacion de Token ___ : Generacion de nuestor token con nuestra llave y nuestro objeto encriptado en SHA256 .
   
```python
# Creamos nuestro encabezado de JWT.
header = {"typ": "JWT", "alg": "HS256"}

# Creamos nuestro cargador de informacion
payload = {"sub": data_usuario["usuario"], "exp": int(time.time()) + 3600, "iat": int(time.time())}

# Creamos un metodo de validacion del cargador con nuestra ionformacion para generar nuestro token.
token = jwt.encode(payload, LLAVE_SECRETA, algorithm="HS256", headers=header)

print(f" Nuestro token sera:   {token} \n")
```
4.  __Desencriptacion de nuestro token__: Cno nuesrta llave secreta desencriptamos nuestro JWT y vemos la infroamcion.
   
```python

#Decoficamos nuestro token para ver el resultado encriptado en nuestra cadena  hash
resultado = jwt.decode(token, LLAVE_SECRETA, algorithms=["HS256"])

print(f"Informacion :   {resultado} \n")
```