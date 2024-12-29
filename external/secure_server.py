import os
import http.server
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization


class SecurityManager:
    def __init__(self, private_key: rsa.RSAPrivateKey, public_key: rsa.RSAPublicKey):
        if not public_key:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()
        self.public_key = public_key
        self.private_key = private_key

    def encrypt_rsa(self, data: bytes) -> str:            
        encrypted = self.public_key.encrypt(
            data,
            padding.PKCS1v15()
        )
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt_rsa(self, encrypted: str) -> bytes:            
        encrypted_bytes = base64.b64decode(encrypted)
        decrypted = self.private_key.decrypt(
            encrypted_bytes,
            padding.PKCS1v15()
        )
        return decrypted

    def encrypt_aes(self, data: bytes, key: bytes) -> str:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        encrypted = nonce + ciphertext
        return base64.b64encode(encrypted).decode('utf-8')


    def decrypt_aes(self, encrypted: str, key: bytes) -> bytes:
        encrypted = base64.b64decode(encrypted)
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)


class SecureHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers["Content-Length"])
        encrypted = self.rfile.read(content_length).decode("utf-8")
        
        decrypted_data = security_manager.decrypt_rsa(encrypted)
        
        if decrypted_data is None:
            self.send_response(400)
            self.end_headers()
            return
            
        decrypted = decrypted_data.decode('utf-8')
        self.send_response(200)
        post_bytes = f"Decrypted data:\n{decrypted}\nNo more data.".encode()
        self.send_header("Content-type", "text/html")
        encrypted_post_bytes = security_manager.encrypt_rsa(post_bytes).encode()
        self.send_header("Content-length", len(encrypted_post_bytes))
        self.end_headers()
        self.wfile.write(encrypted_post_bytes)


with open("private.key", 'rb') as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )


security_manager = SecurityManager(private_key, private_key.public_key())
httpd = http.server.HTTPServer(("0.0.0.0", 8011), SecureHandler)

httpd.serve_forever()
