from itertools import combinations 
import hashlib, os, random, string
from Crypto.Cipher import AES
from dotenv import load_dotenv

def generate_substrings(password):
    substrings = []
    length = round(len(password)/2) - 1
    index_combinations = combinations(range(len(password)), length)

    for indices in index_combinations:
        substring = ''.join(password[i] for i in sorted(indices))
        substrings.append(substring)

    return substrings

def generate_salt():
    salt = os.urandom(64)
    return salt

def hash_password(password, salt):
    hashed_password = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 500000)
    password_hash = salt + hashed_password

    return password_hash.hex()

def hash_substrings(substrings, salt):
    result=''
    for substring in substrings:
        hashed_substring = hashlib.pbkdf2_hmac('sha512', substring.encode('utf-8'), salt, 500000)
        result += hashed_substring.hex()
    return result

def encrypt_length(password_length):
    load_dotenv()
    key = os.getenv("AES_KEY").encode('utf-8')
    password_length_bytes = int.to_bytes(password_length, byteorder='big')
    iv = os.urandom(16) 

    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    ciphertext = cipher.encrypt(password_length_bytes)

    encrypted_length = iv + ciphertext

    return encrypted_length

def decrypt_length(encrypted_data):
    load_dotenv()
    key = os.getenv("AES_KEY").encode('utf-8')

    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    decrypt_cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    decrypted_length_bytes = decrypt_cipher.decrypt(ciphertext)
    decrypted_length = int.from_bytes(decrypted_length_bytes, byteorder='big')  # Remove padding

    return decrypted_length

# def gen_new_user():
#     client_number = (''.join(random.choice('0123456789') for _ in range(10)))
#     password = (''.join(random.choice(string.ascii_letters) for _ in range(8)))




