from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key




message = "secret text".encode('utf-8')

with open("private_key.pem", "rb") as key_file:
    private_key = load_pem_private_key(
        key_file.read(),
        password=None,
    )


ciphertext = private_key.public_key().encrypt(message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(ciphertext)

plaintext = private_key.decrypt(ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(plaintext.decode('utf-8'))
