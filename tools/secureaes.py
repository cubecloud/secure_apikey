import os
import sys
import base64
from typing import Tuple, Union
from Crypto.Cipher import AES
import getpass

__version__ = 0.12


def prepare_phrase(in_phrase):
    bytes_const = 32
    in_phrase_len = len(in_phrase)
    if in_phrase_len == 0:
        sys.exit('Error: phrase has zero length. Exiting...')
    elif in_phrase_len < bytes_const:
        in_phrase = (in_phrase * int(bytes_const // in_phrase_len + 1))[:bytes_const]
    elif in_phrase_len > bytes_const:
        in_phrase = in_phrase[:bytes_const]
    return in_phrase


def ask_4phrase(bytes_limit: Union[int, None], msg_text: str, phrase_name: str) -> str:
    bytes_const = 32
    in_phrase = b""

    if bytes_limit is not None:
        while len(in_phrase) != bytes_limit:
            in_phrase = getpass.getpass(f'{msg_text}')
            in_phrase_len = len(in_phrase)
            if in_phrase_len != bytes_limit:
                print(f"Length of {phrase_name} is {in_phrase_len} bytes, not {bytes_limit} bytes")
                print(f"please correct the {phrase_name} and enter again!")
                continue
            else:
                break
    else:
        in_phrase = getpass.getpass(f'{msg_text}')
        in_phrase = prepare_phrase(in_phrase)
    return in_phrase


def asking_2components_secret(first_part_salt_phrase_len: int = 22, second_part_salt_phrase_len: int = 10) -> bytes:
    """
    Asking for the SALT for encryption divided in two parts

    Returns:
        secret (bytes):     encoded (ascii) secret
    """
    first_part_salt_phrase = ask_4phrase(first_part_salt_phrase_len,
                                         f"Enter the 1st part of SALT phrase, {first_part_salt_phrase_len} bytes ONLY: ",
                                         "1st part of SALT")
    second_part_salt_phrase = ask_4phrase(second_part_salt_phrase_len,
                                          f"Enter the 2nd part of SALT phrase, {second_part_salt_phrase_len} bytes ONLY: ",
                                          "2nd part of SALT")

    user_salt = first_part_salt_phrase + second_part_salt_phrase
    user_salt = user_salt.encode('ascii')
    return user_salt


def asking_1components_secret(salt_phrase_len=None) -> bytes:
    """
    Asking for the SALT for encryption divided in one parts

    Returns:
        secret (bytes):     encoded (ascii) secret
    """
    if salt_phrase_len is not None:
        msg = f"Enter the SALT phrase, {salt_phrase_len} bytes ONLY: "
        user_salt = ask_4phrase(salt_phrase_len, msg, "SALT")
    else:
        msg = f"Enter the SALT phrase: "
        user_salt = ask_4phrase(salt_phrase_len, msg, "SALT")

    user_salt = user_salt.encode('ascii')
    return user_salt


class Secure:

    @staticmethod
    def encrypt(to_encrypt: str, salt: bytes) -> Tuple[bytes, bytes]:
        # First make your data a bytes object. To convert a string to a bytes object, we can call .encode() on it
        to_encrypt_encoded = to_encrypt.encode('utf-8')
        # Create the cipher object and encrypt the data
        cipher_encrypt = AES.new(salt, AES.MODE_CFB)
        ciphered_bytes = cipher_encrypt.encrypt(to_encrypt_encoded)
        iv = cipher_encrypt.iv
        # if self.base64_encode:
        return base64.b64encode(ciphered_bytes), base64.b64encode(iv)
        # else:
        #     return ciphered_bytes, iv

    @staticmethod
    def decrypt(to_decrypt: bytes, salt: bytes, iv: bytes) -> str:
        """
        Args:
            to_decrypt:     encrypted key to decrypt
            salt:           salt from user input
            iv:             data for decryption from previous step

        Returns:
            decrypted_data: decrypted key
        """
        # if self.base64_encode:
        to_decrypt = base64.b64decode(to_decrypt)
        iv = base64.b64decode(iv)
        # Create the cipher object and decrypt the data
        cipher_decrypt = AES.new(salt, AES.MODE_CFB, iv=iv)
        deciphered_bytes = cipher_decrypt.decrypt(to_decrypt)
        # Convert the bytes object back to the string
        try:
            decrypted_data = deciphered_bytes.decode('utf-8')
        except UnicodeDecodeError as error_msg:
            sys.exit(f"Error: Wrong salt, {error_msg}")
        return decrypted_data

    @staticmethod
    def check_env(env_list: list) -> bool:
        env_OK = False
        env_values_list = [os.environ.get(name) for name in env_list]
        if None not in env_values_list:
            env_OK = True
        return env_OK

    @staticmethod
    def get_decrypted_data(env_names_list, secret_phrase):
        env_values_list = [os.environ.get(name) for name in env_names_list]
        env_values_list = [value.encode('ascii') for value in env_values_list]

        """ Getting encrypted key parts from environment """
        parse_key = env_values_list[0]
        parse_secret = env_values_list[1]
        parse_key_iv = env_values_list[2]
        parse_secret_iv = env_values_list[3]

        """ Decrypt key and secret """
        key = Secure.decrypt(parse_key, secret_phrase, parse_key_iv)
        secret = Secure.decrypt(parse_secret, secret_phrase, parse_secret_iv)
        return key, secret

    #   alias for get_key
    @staticmethod
    def get_api_key(prefix: str = '', use_env_salt: bool = False):
        return Secure.get_x_data(prefix, use_env_salt, key_names=('KEY', 'SECRET'))

    @staticmethod
    def get_key(prefix: str = '', use_env_salt: bool = False):
        return Secure.get_x_data(prefix, use_env_salt, key_names=('KEY', 'SECRET'))

    @staticmethod
    def get_username_password(prefix: str = '', use_env_salt: bool = False):
        return Secure.get_x_data(prefix, use_env_salt, key_names=('USERNAME', 'PASSWORD'))

    @staticmethod
    def get_x_data(prefix: str = '', use_env_salt: bool = False, key_names=('USERNAME', 'PASSWORD')):
        prefix = prefix.upper()
        env_names_list = [f"{prefix}PARSE_{key_names[0]}", f"{prefix}PARSE_{key_names[1]}",
                          f"{prefix}PARSE_{key_names[0]}_IV", f"{prefix}PARSE_{key_names[1]}_IV"]
        if not Secure.check_env(env_names_list):
            keys_filename = f'{prefix}KEYS.env' if prefix != '' else 'KEYS.env'
            msg = (f'Encrypted {key_names[0]} and {key_names[1]} not found in environment variables,'
                   f'\nplease create create keys!')
            print(msg)
            print()
            Secure.encrypt_username_password(keys_filename, prefix=prefix, only_show=False)
            msg = f'Warning! Data encrypted and saved to {keys_filename}. Set the ENV and please restart application!'
            sys.exit(msg)

        """ Getting salt parts """
        if use_env_salt:
            if not Secure.check_env([f'{prefix.upper()}_KEY']):
                print(f'ENV with prefix {prefix} is not set!')
                secret_phrase: bytes = asking_1components_secret()
            else:
                secret_phrase = prepare_phrase(Secure.get_env_value(f'{prefix.upper()}_KEY').encode('ascii'))
        else:
            print(f'ENV with prefix {prefix} is not set')
            secret_phrase: bytes = asking_1components_secret()
        return Secure.get_decrypted_data(env_names_list, secret_phrase)

    @staticmethod
    def get_env_value(env_name: str):
        if not Secure.check_env([env_name]):
            msg = f'ENV {env_name} not found, add ENV environment variable(s)!'
            sys.exit(msg)
        salt_env_value = os.environ.get(env_name)
        return salt_env_value

    @staticmethod
    def encrypt_keys(filename: str = 'KEYS.env', only_show: bool = True, prefix: str = '') -> None:
        """
        Args:
            filename (str):     filename for dot env file
            only_show (bool):   Do not write data to file. Show on screen only
            prefix (str):       prefix for variables
        """
        if len(prefix) > 1:
            prefix = prefix.upper()
            filename = f'{prefix}{filename}'

        secret_phrase = asking_2components_secret()
        print()
        Secure.encrypt_x(filename=filename, only_show=only_show, prefix=prefix,
                         key_names=['KEY', 'SECRET'], secret_phrase=secret_phrase)

    @staticmethod
    def encrypt_username_password(filename: str = 'KEYS.env', only_show: bool = True, prefix: str = '') -> None:
        """
        Args:
            filename (str):     filename for dot env file
            only_show (bool):   Do not write data to file. Show on screen only
            prefix (str):       prefix for variables
        """
        if len(prefix) > 1:
            prefix = prefix.upper()
            filename = f'{prefix}{filename}'

        secret_phrase = asking_1components_secret(salt_phrase_len=None)
        Secure.encrypt_x(filename=filename, only_show=only_show, prefix=prefix,
                         key_names=['USERNAME', 'PASSWORD'], secret_phrase=secret_phrase)

    @staticmethod
    def encrypt_x(filename: str = 'KEYS.env', only_show: bool = True, prefix: str = '',
                  key_names=('USERNAME', 'PASSWORD'), secret_phrase=None) -> None:
        """
        Args:
            filename (str):             filename for dot env file
            only_show (bool):           Do not write data to file. Show on screen only
            prefix (str):               prefix for variables
            key_names (list):           key names for variable and messaging
            secret_phrase (str, None):  secret phrase
        """

        if secret_phrase is None:
            secret_phrase = asking_1components_secret(salt_phrase_len=None)
            print()

        if len(prefix) > 1:
            prefix = prefix.upper()
            filename = f'{prefix}{filename}'

        key_one_to_encrypt = getpass.getpass(f'Enter the {prefix} {key_names[0]} to encrypt: ')
        key_two_to_encrypt = getpass.getpass(f'Enter the {prefix} {key_names[1]} to encrypt: ')

        secure_key = Secure()
        print(f'{key_names[0]} encryption...')
        key_one_encrypted_base64, key_one_iv_base64 = secure_key.encrypt(key_one_to_encrypt, secret_phrase)
        print(f'{key_names[0]} decryption...')
        key_one_decrypted = secure_key.decrypt(key_one_encrypted_base64, secret_phrase, key_one_iv_base64)
        if key_one_to_encrypt == key_one_decrypted:
            print('Original data match the result!')
        else:
            print('Original data does not match the result\n')
            msg = f'Encrypted & decrypted {key_names[0]}: \n{key_one_to_encrypt}\n{key_one_decrypted}'
            del key_one_to_encrypt
            del key_two_to_encrypt
            sys.exit(msg)

        print(f'{key_names[1]} encryption...')
        key_two_encrypted_base64, key_two_iv_base64 = secure_key.encrypt(key_two_to_encrypt, secret_phrase)

        print(f'{key_names[1]} decryption...')
        key_two_decrypted = secure_key.decrypt(key_two_encrypted_base64, secret_phrase, key_two_iv_base64)

        if key_two_to_encrypt == key_two_decrypted:
            print('Original data match the result!\n')
        else:
            print('Original data does not match the result!\n')
            msg = f'Encrypted & decrypted {key_names[1]}: \n{key_two_to_encrypt}\n{key_two_decrypted}'
            del key_one_to_encrypt
            del key_two_to_encrypt
            sys.exit(msg)

        if only_show:
            print(f"Encrypted {key_names[0]}:", key_one_encrypted_base64)
            print(f"Encrypted {key_names[0]} iv:", key_one_iv_base64)

            print(f'Encrypted {key_names[1]}: {key_two_encrypted_base64}')
            print(f'Encrypted {key_names[1]} iv: {key_two_iv_base64}')
        else:
            sys.stdout = open(filename, 'w')
            sys.stdout.buffer.write(
                (bytes(f'{prefix}PARSE_{key_names[0]}=', 'utf-8')) + key_one_encrypted_base64 + (bytes('\n', 'utf-8')))
            sys.stdout.buffer.write(
                (bytes(f'{prefix}PARSE_{key_names[1]}=', 'utf-8')) + key_two_encrypted_base64 + (bytes('\n', 'utf-8')))
            sys.stdout.buffer.write(
                (bytes(f'{prefix}PARSE_{key_names[0]}_IV=', 'utf-8')) + key_one_iv_base64 + (bytes('\n', 'utf-8')))
            sys.stdout.buffer.write(
                (bytes(f'{prefix}PARSE_{key_names[1]}_IV=', 'utf-8')) + key_two_iv_base64 + (bytes('\n', 'utf-8')))
            sys.stdout.close()
        del key_one_to_encrypt
        del key_two_to_encrypt
        del secure_key


if __name__ == '__main__':
    # Secure.encrypt_keys(filename='testenv', only_show=False)
    # prepare environment key set for username and password
    # Secure.encrypt_username_password(prefix='OPTUNA', only_show=False)
    # check the environment set (LOAD it in IDE config file, or set them in batch file for environment)
    print(Secure.get_username_password(prefix='PSGSQL', use_env_salt=True))
