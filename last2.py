# encryption_tool/encryption.py
from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def encrypt_message(message, key):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message

# encryption_tool/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('encrypt/', views.encrypt, name='encrypt'),
    path('decrypt/', views.decrypt, name='decrypt'),
]

# encryption_tool/views.py
from django.http import JsonResponse
from .encryption import generate_key, encrypt_message, decrypt_message
import base64

def encrypt(request):
    if request.method == 'POST':
        message = request.POST.get('message')
        key = generate_key()
        encrypted_message = encrypt_message(message, key)
        return JsonResponse({'encrypted_message': base64.urlsafe_b64encode(encrypted_message).decode(), 'key': base64.urlsafe_b64encode(key).decode()})
    return JsonResponse({'error': 'POST method required'})

def decrypt(request):
    if request.method == 'POST':
        encrypted_message = request.POST.get('encrypted_message')
        key = request.POST.get('key')
        decrypted_message = decrypt_message(base64.urlsafe_b64decode(encrypted_message.encode()), base64.urlsafe_b64decode(key.encode()))
        return JsonResponse({'decrypted_message': decrypted_message})
    return JsonResponse({'error': 'POST method required'})

# encryption_project/urls.py
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('encryption/', include('encryption_tool.urls')),
]
from cryptography.fernet import Fernet

# Replace 'your_secret_key_here' with your actual secret key
SECRET_KEY = b'your_secret_key_here'

class EncryptionMiddleware:
    def _init_(self, get_response):
        self.get_response = get_response
        self.key = SECRET_KEY
        self.cipher = Fernet(self.key)

    def _call_(self, request):
        # Decrypt incoming request
        if 'encrypted_data' in request.POST:
            encrypted_data = request.POST['encrypted_data'].encode()
            decrypted_data = self.cipher.decrypt(encrypted_data).decode()
            request.POST = request.POST.copy()
            request.POST['data'] = decrypted_data
        
        response = self.get_response(request)

        # Encrypt outgoing response
        if response.status_code == 200 and 'data' in response.content.decode():
            data = response.content.decode()
            encrypted_data = self.cipher.encrypt(data.encode()).decode()
            response.content = encrypted_data
        
        return response
    from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

app = Flask(_name_)

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_text(text, public_key):
    ciphertext = public_key.encrypt(
        text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_text(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

@app.route('/encrypt_rsa', methods=['POST'])
def encrypt_rsa():
    try:
        data = request.get_json()
        text = data.get('text')

        if not text:
            return jsonify({'result': 'error', 'message': 'Text input is missing.'}), 400

        private_key, public_key = generate_rsa_key_pair()
        encrypted_text = encrypt_text(text, public_key)

        return jsonify({
            'result': 'success',
            'encrypted_text': encrypted_text.hex(),
            'public_key': public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        })
    except Exception as e:
        return jsonify({'result': 'error', 'message': str(e)}), 500

@app.route('/decrypt_rsa', methods=['POST'])
def decrypt_rsa():
    try:
        data = request.get_json()
        encrypted_text_hex = data.get('encrypted_text')
        private_key_pem = data.get('private_key')

        if not (encrypted_text_hex and private_key_pem):
            return jsonify({'result': 'error', 'message': 'Missing required data.'}), 400

        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None
        )
        encrypted_text = bytes.fromhex(encrypted_text_hex)
        decrypted_text = decrypt_text(encrypted_text, private_key)

        return jsonify({
            'result': 'success',
            'decrypted_text': decrypted_text
        })
    except Exception as e:
        return jsonify({'result': 'error', 'message': str(e)}), 500

if _name_ == '_main_':
    app.run(debug=True)