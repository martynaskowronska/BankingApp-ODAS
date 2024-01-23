# client number: 8364170199
# password: JreCmTdJ

from itertools import combinations 
import hashlib, os, random, string
from Crypto.Cipher import AES
from dotenv import load_dotenv
from website.models import User, UserInfo, Permutation
from website import db, create_app

def generate_substrings(password):
    substrings = []
    length = len(password) - (round(len(password)/2) - 1)
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

    return hashed_password.hex()

def hash_substrings(substrings, salt):
    result=''
    for substring in substrings:
        hashed_substring = hash_password(substring, salt)
        result += hashed_substring
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

def encrypt_length(password_length):
    load_dotenv()
    key = os.getenv("AES_KEY").encode('utf-8')
    password_length_bytes = int.to_bytes(password_length, byteorder='big')
    iv = os.urandom(16) 

    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    ciphertext = cipher.encrypt(password_length_bytes)

    encrypted_length = iv + ciphertext

    return encrypted_length

def decrypt_length(encrypted_password):
    load_dotenv()
    key = os.getenv("AES_KEY").encode('utf-8')

    iv = encrypted_password[:16]
    ciphertext = encrypted_password[16:]

    decrypt_cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    decrypted_length_bytes = decrypt_cipher.decrypt(ciphertext)
    decrypted_length = int.from_bytes(decrypted_length_bytes, byteorder='big')  # Remove padding

    return decrypted_length

def encrypt_data(data):
    load_dotenv()
    key = os.getenv("AES2_KEY").encode('utf-8')
    iv = os.urandom(16) 

    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    cipher_text = cipher.encrypt(data.encode('utf-8'))

    encrypted_length = iv + cipher_text

    return encrypted_length

def decrypt_data(encrypted_data):
    load_dotenv()
    key = os.getenv("AES2_KEY").encode('utf-8')

    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    decrypt_cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    decrypted_data = decrypt_cipher.decrypt(ciphertext)

    return decrypted_data.decode('utf-8')

def gen_new_user():
    client_number = (''.join(random.choice('0123456789') for _ in range(10)))
    password = (''.join(random.choice(string.ascii_letters) for _ in range(8)))
    salt = generate_salt()
    hash_pswd = hash_password(password, salt)
    enc_pswd_len = encrypt_length(8)
    pswd_permutations = generate_substrings(password)
    pswd_hash_permutations = hash_substrings(pswd_permutations, salt)

    print(client_number)
    print(password)

    first_name = "Jan"
    last_name = "Kowalski"
    balance = 10000
    id_number = 'ABC123456'
    card_number = "1234 5678 9012 3456"
    enc_id_number = encrypt_data(id_number)
    enc_card_number = encrypt_data(card_number)

    app = create_app()
    with app.app_context():
        new_user = User(client_number = client_number, password = hash_pswd, password_length = enc_pswd_len, salt = salt)
        db.session.add(new_user)
        new_permutation = Permutation(client_number = client_number, permutations = pswd_hash_permutations)
        db.session.add(new_permutation)
        new_user_info = UserInfo(client_number = client_number, first_name = first_name, last_name = last_name, balance=balance, id_number = enc_id_number, card_number = enc_card_number)
        db.session.add(new_user_info)
        db.session.commit()

    print('User created!')