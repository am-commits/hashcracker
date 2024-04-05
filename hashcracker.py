"""
Created on Fri Apr  5 18:18:20 2024

@author: Andreas Michailidis
"""

import hashlib

def md5_hash(text):
    """Calculate the MD5 hash of a text."""
    return hashlib.md5(text.encode()).hexdigest()

def sha256_hash(text):
    """Calculate the SHA-256 hash of a text."""
    return hashlib.sha256(text.encode()).hexdigest()

def brute_force(md5_target_hash, sha256_target_hash, algorithm, max_length=6, charset='abcdefghijklmnopqrstuvwxyz'):
    """Brute force hash."""
    if algorithm == 'md5':
        target_hash = md5_target_hash
        hash_function = md5_hash
    elif algorithm == 'sha256':
        target_hash = sha256_target_hash
        hash_function = sha256_hash
    else:
        raise ValueError("Invalid algorithm. Please choose 'md5' or 'sha256'.")

    for length in range(1, max_length + 1):
        for password in generate_passwords(charset, length):
            hashed_password = hash_function(password)
            if hashed_password == target_hash:
                return password
    return None

def generate_passwords(charset, length):
    """Generate all possible passwords of a given length from a given character set."""
    if length == 0:
        yield ''
    else:
        for char in charset:
            for password in generate_passwords(charset, length - 1):
                yield char + password

if __name__ == "__main__":
    algorithm = input("Enter the hashing algorithm (md5 or sha256): ").strip().lower()
    if algorithm not in ['md5', 'sha256']:
        print("Invalid algorithm. Please choose 'md5' or 'sha256'.")
    else:
        if algorithm == 'md5':
            target_hash = input("Enter the MD5 hash value: ").strip()
            password = brute_force(md5_target_hash=target_hash, sha256_target_hash=None, algorithm='md5')
        else:  # algorithm == 'sha256'
            target_hash = input("Enter the SHA-256 hash value: ").strip()
            password = brute_force(md5_target_hash=None, sha256_target_hash=target_hash, algorithm='sha256')

        if password:
            print("Password found:", password)
        else:
            print("Password not found.")
