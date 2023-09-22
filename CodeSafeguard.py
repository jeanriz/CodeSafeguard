import base64
import hashlib
import secrets
import sys

from termcolor import colored

banner = """
 _____           _      _____        __                               _ 
/  __ \         | |    /  ___|      / _|                             | |
| /  \/ ___   __| | ___\ `--.  __ _| |_ ___  __ _ _   _  __ _ _ __ __| |
| |    / _ \ / _` |/ _ \`--. \/ _` |  _/ _ \/ _` | | | |/ _` | '__/ _` |
| \__/\ (_) | (_| |  __/\__/ / (_| | ||  __/ (_| | |_| | (_| | | | (_| |
 \____/\___/ \__,_|\___\____/ \__,_|_| \___|\__, |\__,_|\__,_|_|  \__,_|
                                             __/ |                      
                                            |___/                                  
"""
green_logo = colored("[*]", "green")
blue_logo = colored("[*]", "blue")

def generate_random_key(length=32):
    key = secrets.token_bytes(length)
    return key[:32]  # Truncate the key to a maximum of 32 characters

def xor_encrypt(text, key):
    encrypted = bytearray(text, 'utf-8')
    for i in range(len(encrypted)):
        encrypted[i] ^= key[i % len(key)]
    return encrypted

# ...

def obfuscate_script(script_path, key, script_output):
    # Read the content of the script to obfuscate
    with open(script_path, 'r', encoding='utf-8') as script_file:
        script_content = script_file.read()

    # Generate a random XOR key, maximum length of 32 characters
    xor_key = generate_random_key()
    print(blue_logo, " Generating encryption key ... \n")
    
    # Encrypt the content using XOR
    encrypted_script = xor_encrypt(script_content, xor_key)
    print(green_logo, " XOR encryption ... \n")
    
    # Encode the encrypted content in base64
    base64_script = base64.b64encode(encrypted_script).decode('utf-8')
    print(green_logo, " Base64 encoding ... \n")
    
    # Calculate the SHA-256 hash of the encrypted content
    sha256_hash = hashlib.sha256(encrypted_script).hexdigest()

    # Create a self-deobfuscation script with the included XOR key
    template = f'''
import base64
import hashlib
import sys
import subprocess

def xor_decrypt(encrypted, key):
    decrypted = bytearray(encrypted)
    for i in range(len(decrypted)):
        decrypted[i] ^= key[i % len(key)]
    return decrypted

def deobfuscate_and_execute(obfuscated_script, key):
    xor_key = "{xor_key.hex()}"
    encrypted_script = base64.b64decode(obfuscated_script.encode())
    decrypted_script = xor_decrypt(encrypted_script, bytes.fromhex(xor_key))

    original_hash = hashlib.sha256(encrypted_script).hexdigest()

    if original_hash == "{sha256_hash}":
        exec(decrypted_script.decode('utf-8'))

    else:
        print("The script has been tampered with and cannot be executed.")

if __name__ == '__main__':
    obfuscated_script = "{base64_script}"
    deobfuscate_and_execute(obfuscated_script, None)
    '''

    # Write the self-deobfuscation script to a file
    with open(script_output, 'w', encoding='utf-8') as output_file:
        output_file.write(template)
    print(green_logo, " Writing the template ... \n")
    print(blue_logo, f" The script has been successfully obfuscated, and the template script has been created in {script_output}. \n")

if __name__ == '__main__':
    print(banner + "\n\n\n")
    script_path = input(f"{colored('[?] ', 'blue')} Enter the path of the script to obfuscate: ")
    script_output = input(f"{colored('[?] ', 'blue')} Enter the output file: ")
    obfuscate_script(script_path, None, script_output)
