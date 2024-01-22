from itertools import combinations 
import hashlib
import os

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


