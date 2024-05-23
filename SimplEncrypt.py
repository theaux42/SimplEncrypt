from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from getpass import getpass
from colorama import Fore, init
from time import sleep
import os

def print_error(message):
    print(Fore.RED + message)

def encrypt_file(file_name, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=1000000, hmac_hash_module=SHA256)
    cipher = AES.new(key, AES.MODE_CBC)
    with open(file_name, 'rb') as f:
        plaintext = f.read()
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    enc_file_name = os.path.join(os.path.dirname(file_name), "enc_" + os.path.basename(file_name))
    with open(enc_file_name, 'wb') as f:
        f.write(salt)
        f.write(cipher.iv)
        f.write(ciphertext)

def decrypt_file(file_name, password):
    with open(file_name, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()
    key = PBKDF2(password, salt, dkLen=32, count=1000000, hmac_hash_module=SHA256)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except ValueError:
        print_error("Invalid password! Please try again.")
        quit()
    clear_file_name = file_name.replace("enc_", "clear_")
    with open(clear_file_name, 'wb') as f:
        f.write(plaintext)

def file_selector():
    files = [file for file in os.listdir() if file != os.path.basename(__file__)]
    file_dict = {i: file for i, file in enumerate(files, start=1)}
    
    for id, file in file_dict.items():
        print(f"{Fore.RESET}[{Fore.MAGENTA}{id}{Fore.RESET}] => {file}")
    
    try:
        file_id = int(input("Enter the id of the file >>> "))
    except ValueError:
        clear_screen()
        print_error("Invalid id. Please try again.")
        sleep(0.3)
        clear_screen()
        return file_selector()
    selected_file = file_dict.get(file_id, None)
    
    if selected_file is None:
        clear_screen()
        print_error("Invalid id. Please try again.")
        sleep(0.3)
        clear_screen()
        return file_selector()
    
    return selected_file

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    clear_screen()
    print(Fore.MAGENTA + """
   _____ _                 _ ______                             _   
  / ____(_)               | |  ____|                           | |  
 | (___  _ _ __ ___  _ __ | | |__   _ __   ___ _ __ _   _ _ __ | |_ 
  \___ \| | '_ ` _ \| '_ \| |  __| | '_ \ / __| '__| | | | '_ \| __|
  ____) | | | | | | | |_) | | |____| | | | (__| |  | |_| | |_) | |_ 
 |_____/|_|_| |_| |_| .__/|_|______|_| |_|\___|_|   \__, | .__/ \__|
                    | |                              __/ | |        
                    |_|                             |___/|_|        
    """)
    print(f"Welcome to the {Fore.MAGENTA}SimplEncrypt{Fore.RESET} !\n")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    print("3. Exit\n")
    choice = input(f">>> {Fore.MAGENTA}")
    clear_screen()
    if choice == "1":
        file_name = file_selector()
        password = getpass("Enter the password to encrypt the file >>> ")
        confirm_password = getpass("Confirm the password >>> ")
        if password != confirm_password:
            print_error("Passwords do not match. Please try again.")
            sleep(0.5)
            return main()
        encrypt_file(file_name, password)
        clear_screen()
        print(Fore.GREEN+"File encrypted successfully!")
    elif choice == "2":
        file_name = file_selector()
        password = getpass("Enter the password to decrypt the file >>> ")
        confirm_password = getpass("Confirm the password >>> ")
        if password != confirm_password:
            print_error("Passwords do not match. Please try again.")
            sleep(0.5)
            return main()
        decrypt_file(file_name, password)
        clear_screen()
        print(Fore.GREEN+"File decrypted successfully!")
    elif choice == "3":
        print(Fore.RED+"Exiting the program...")
        quit()
    else:
        print_error("Invalid choice! Please enter 1 or 2.")
        main()


if __name__ == "__main__":
    init(autoreset=True)
    try:
        main()
    except KeyboardInterrupt:
        clear_screen()
        print(Fore.RED+"Exiting the program...")