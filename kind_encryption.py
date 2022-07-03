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
    password = bytes(password, encoding='utf-8')
    return hashlib.sha256(password).digest()


def get_password():
    os.system('cls')
    print("Введите пароль ниже")
    
    while True:
        password = getpass.getpass()
        if len(password) < 6:
            print("Введите более надежный пароль\n")
            continue
        break
    return password


def encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024) -> None:
    if not out_filename:
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


def decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024):
    if not out_filename:
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

def remove_data(all_files):
    choice = input("Файлы зашифрованы, что делаем с оригиналом?\n\
                1) Безопасно удалить оригинал (безопасно)\n\
                2) Удалить оригинал обычным способом (небезопасно)\n\
                3) Не удалять оригинальные файлы\n-->  ")
    
    try:
        choice = int(choice)
    except:
        return
    
    match choice:
        case 1:
            print("Приступаем к удалению")
            for file in all_files:
                print("{} ".format(file.split('\\')[-1]), end='')
                secure_delete.secure_delete(file)
                print(termcolor.colored("  done", "green"))
        case 2:
            for file in all_files:
                print("Удаляем исходник... ", end='')
                os.remove(file)
                print(termcolor.colored("  done", "green"))
        case _:
            return
        
        
    print("Готово!")
    time.sleep(3)
    return

def encrypt_data(key) -> None:
    while True:
        secure_delete.secure_random_seed_init()
        os.system('cls')
        path = input("Введите путь до файла или папки \nEnter, чтобы вернуться\n --> ")
        if not path:
            return
        
        if len(path) < 3:
            print("Кажется имя не может быть таким коротким\n")
            time.sleep(3)
            os.system('cls')
            continue
        
        if os.path.isfile(path):
            print("Приступаем к шифрованию файла...")
            encrypt_file(key, path)
            print("Безопасно удаляем исходник")
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
            
            print("Приступаем к шифрованию файлов в папке")
            for file in all_files:
                print('{}'.format(file.split('\\')[-1]), end = '')
                encrypt_file(key, file)
                print(termcolor.colored("  done", "green"))
            
            remove_data(all_files)
            return
        else:
            print("По данному пути, ничего не найдено")
            time.sleep(3)
            continue


def decrypt_data(key) -> None:
    while True:
        os.system('cls')
        path = input("Введите путь до файла или Enter, чтобы вернуться\n-->  ")
        if not path:
            return
        
        if len(path) < 3:
            print("Кажется имя не может быть таким коротким\n")
            time.sleep(3)
            os.system('cls')
            continue
        
        if os.path.isfile(path):
            print("Приступаем к расшифровке файла...")
            decrypt_file(key, path)
            print("Файл расшифрован")
            choice = input("1) Удалить исходник? (проверьте, правильно ли расшифрован файл)\n2) Не удалять\n-->  ")
            try:
                choice = int(choice)
                if choice != 1:
                    choice = 2
            except:
                choice = 2
            
            if choice == 1:
                os.remove(path)
                print("Готово!")
            else:
                print("Хорошо, удалять не будем")
            time.sleep(3)
            return
        elif os.path.isdir(path):
            all_files = []
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file[-5:] != '.kind':
                        continue
                    all_files.append(root + '\\' + file)
            
            print("Приступаем к расшифровке файлов в папке")
            for file in all_files:
                print('{}'.format(file.split('\\')[-1]), end = '')
                decrypt_file(key, file)
                print(termcolor.colored("  done", "green"))
            
            print("Файлы расшифрованы")
            choice = input("1) Удалить исходники? (проверьте, правильно ли расшифрованы файлы)\n2) Не удалять\n-->  ")
            try:
                choice = int(choice)
                if choice != 1:
                    choice = 2
            except:
                choice = 2
                
            if choice == 1:
                for file in all_files:
                    os.remove(file)
                print("Готово!")
            else:
                print("Хорошо, удалять не будем")
            time.sleep(3)
            return
        else:
            print("По данному пути, ничего не найдено")
            time.sleep(3)
            continue


def submit_pass():
    password = print("Пожалуйста подтвердите пароль\n")
    password = getpass.getpass()
    return hashing_password(password)
    

def main():
    print("При зашифровке, будут пропущены файлы с расширением .kind")
    print("При расшифровке, будут пропущены файлы без расширения .kind")
    time.sleep(4)
    # Получаем пароль
    password = get_password()
    # Шифруем алгоритмом sha256
    key = hashing_password(password)
    
    while True:
        os.system('cls')
        choice = input("Выберите цифру, под необходимым действием\n\
                1) Зашифровать файл или файлы в папке (файлы в подпапках также будут зашифрованы)\n\
                2) Расшифровать файл или файлы в папке (файлы в подпапках также будут расшифрованы)\n-->  ")
        try:
            choice = int(choice)
        except:
            print("Введите число!")
            time.sleep(3)
            continue
        
        match choice:
            case 1:
                if submit_pass() != key:
                    print("Кажется пароль, не совпал с тем, что ты ввел вначале")
                    time.sleep(3)
                    continue
                encrypt_data(key)    
            case 2:
                decrypt_data(key)
            case _:
                continue
        
    
if __name__ == '__main__':
    main()
