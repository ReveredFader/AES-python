from Crypto.Cipher import AES
from secure_delete import secure_delete
import getpass
import hashlib
import struct
import os
import time
import termcolor


def hashing_password(password: str):
    """ Хеширование пароля """
    bytes_password = bytes(password, encoding='utf-8')
    return hashlib.sha256(bytes_password).digest()


def get_password() -> str:
    """ Получение пароля """
    os.system('cls')
    print("Enter the password")
    
    while True:
        password = getpass.getpass()
        if len(password) < 6:
            print("Enter a stronger password\n")
            continue
        break
    return password


def encrypt_file(key, in_filename:str, chunksize=64*1024) -> None:
    out_filename = in_filename + '.kind'
    
    iv = os.urandom(64)
    encryptor = AES.new(key, AES.MODE_EAX, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 64 != 0:
                    chunk += b' ' * (64 - len(chunk) % 64)

                outfile.write(encryptor.encrypt(chunk))


def decrypt_file(key, in_filename: str, chunksize=24*1024) -> None:
    out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(64)
        decryptor = AES.new(key, AES.MODE_EAX, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)

def remove_data(all_files) -> None:
    choice = input("The files are encrypted, what do we do with the original?\n\
                1) Secure delete the original\n\
                2) Delete the original in the usual way\n\
                3) Do not delete original files\n-->  ")
    
    try:
        choice = int(choice)
    except:
        return
    
    match choice:
        case 1:
            print("Proceed to delete")
            for file in all_files:
                print("{} ".format(file.split('\\')[-1]), end='')
                secure_delete.secure_delete(file)
                print(termcolor.colored("  done", "green"))
        case 2:
            for file in all_files:
                print("{} ".format(file.split('\\')[-1]), end='')
                try:
                    os.remove(file)
                    print(termcolor.colored("  done", "green"))
                except:
                    print(termcolor.colored("  the file wasn't found", "red"))
        case _:
            return
        
    print("Done!")
    time.sleep(3)
    return


def encrypt_data(key) -> None:
    while True:
        secure_delete.secure_random_seed_init()
        os.system('cls')
        path = input("Enter the path to the file or folder \nEnter to return\n --> ")
        if not path:
            return
        
        if len(path) < 3:
            print("It seems the name can't be so short\n")
            time.sleep(3)
            os.system('cls')
            continue
        
        if os.path.isfile(path):
            print("File encryption started...")
            encrypt_file(key, path)
            print("Secure removing the source file")
            secure_delete.secure_delete(path)
            print("Готово!")
            time.sleep(3)
            return
        
        elif os.path.isdir(path):
            all_files = []
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file[-5:] == '.kind':
                        continue
                    all_files.append(root + '\\' + file)
            
            print("Encryption of files in the folder has started")
            for file in all_files:
                print('{}'.format(file.split('\\')[-1]), end = '')
                encrypt_file(key, file)
                print(termcolor.colored("  done", "green"))
            
            remove_data(all_files)
            return
        else:
            print("On this path, nothing was found")
            time.sleep(3)
            continue


def decrypt_data(key) -> None:
    while True:
        os.system('cls')
        path = input("Enter the path to the file or Enter to return\n-->  ")
        if not path:
            return
        
        if len(path) < 3:
            print("It seems the name can't be so short\n")
            time.sleep(3)
            os.system('cls')
            continue
        
        if os.path.isfile(path):
            print("Decryption of the file has begun...")
            decrypt_file(key, path)
            print("The file has been decrypted")
            choice = input("1) Delete the original file? (check if the file is decrypted correctly)\n2) Do not delete\n-->  ")
            try:
                choice = int(choice)
                if choice == 1:
                    try:
                        os.remove(path)
                        print(termcolor.colored("Done!", "green"))
                    except FileNotFoundError:
                        print(termcolor.colored("The file wasn't found!", "red"))
                else:
                    print("Okay, we won't delete it")
            except:
                print("It's unclear what you have entered, but the file will not be deleted")
                
            time.sleep(3)
            return
        elif os.path.isdir(path):
            all_files = []
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file[-5:] != '.kind':
                        continue
                    all_files.append(root + '\\' + file)
            
            print("Decryption of files in the folder has begun")
            for file in all_files:
                print('{}'.format(file.split('\\')[-1]), end = '')
                decrypt_file(key, file)
                print(termcolor.colored("  done", "green"))
            
            print("The files have been decrypted")
            choice = input("1) Delete the source files? (check if the file is decrypted correctly)\n2)  Do not delete\n-->  ")
            try:
                choice = int(choice)
                if choice == 1:
                    for file in all_files:
                        os.remove(file)
                    print("Done!")
                else:
                    print("Okay, we won't delete it")
            except:
                print("It is unclear what you have entered, but the files will not be deleted")
            
            time.sleep(3)
            return
        else:
            print("On this path, nothing was found")
            time.sleep(3)
            continue


def submit_pass():
    password = print("Please confirm your password\n")
    password = getpass.getpass()
    return hashing_password(password)
    

def main():
    print("When encrypted, files with .kind will be skipped")
    print("When decrypting, files without .kind will be skipped")
    time.sleep(4)
    # Получаем пароль
    password = get_password()
    # Получаем хеш алгоритмом sha256
    key = hashing_password(password)
    
    while True:
        os.system('cls')
        choice = input("Select a number\n\
                1) Encrypt a file or files in a folder (files in subfolders will also be encrypted)\n\
                2) Decrypt a file or files in a folder (files in subfolders will also be decrypted)\n-->  ")
        try:
            choice = int(choice)
        except:
            print("Enter a number!")
            time.sleep(3)
            continue
        
        match choice:
            case 1:
                if submit_pass() != key:
                    print("It seems the password didn't match what you entered at the beginning")
                    time.sleep(3)
                    continue
                encrypt_data(key)    
            case 2:
                decrypt_data(key)
            case _:
                continue
        
    
if __name__ == '__main__':
    main()