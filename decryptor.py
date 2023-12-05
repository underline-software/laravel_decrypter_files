from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import json
import os

SCRIPT_DIRECTORY = '16614'
KEY_LARAVEL= "44 character key"

def save_to_file(binary_data, file_path):
    name, extension = os.path.splitext(file_path)
    new_name = f"{name}_d{extension}"
    with open(new_name, 'wb') as file:
        file.write(binary_data)
def get_encrypted_content(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
        return content
def laravel_decrypt(encrypted_value, key, iv):
    key = bytes.fromhex(key)
    iv = bytes.fromhex(iv)
    encrypted_value = base64.b64decode(encrypted_value)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_value = decryptor.update(encrypted_value) + decryptor.finalize()
    return decrypted_value
def remove_padding(data):
    padding_length = data[-1]
    unpadded_data = data[:-padding_length]
    return unpadded_data
for file_name in os.listdir(SCRIPT_DIRECTORY):
    file_path = os.path.join(SCRIPT_DIRECTORY, file_name)
    if os.path.isfile(file_path):
        encrypted_data = base64.b64decode(get_encrypted_content(file_path))
        encrypted_data = json.loads(encrypted_data)
        decrypted_value = laravel_decrypt(
            encrypted_data['value'],
            base64.b64decode(KEY_LARAVEL).hex(),
            base64.b64decode(encrypted_data['iv']).hex()
        )
        save_to_file(remove_padding(decrypted_value), file_path)
        print('decrypted: ', file_path, '\n')
