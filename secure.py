import os
import sys
import base64
from typing import Tuple
from Crypto.Cipher import AES
import getpass

__version__ = 0.0017


def ask_4phrase(bytes_limit: int, msg_text: str, phrase_name: str) -> str:
    in_phrase = b""
    while len(in_phrase) != bytes_limit:
        in_phrase = getpass.getpass(f'{msg_text}')
        in_phrase_len = len(in_phrase)
        if len(in_phrase) != bytes_limit:
            print(f"Length of {phrase_name} is {in_phrase_len} bytes, not {bytes_limit} bytes")
            print(f"please correct the {phrase_name} and enter again!")
            continue
        else:
            break
    return in_phrase


def asking_2components_secret() -> bytes:
    """
    Asking for the SALT for encryption divided in two parts

    Returns:
        secret (bytes):     encoded (ascii) secret
    """
    first_part_salt_phrase_len = 22
    first_part_salt_phrase = ask_4phrase(first_part_salt_phrase_len,
                                         f"Enter the 1st part of SALT phrase, {first_part_salt_phrase_len} bytes ONLY: ",
                                         "1st part of SALT")
    second_part_salt_phrase_len = 10
    second_part_salt_phrase = ask_4phrase(second_part_salt_phrase_len,
                                          f"Enter the 2nd part of SALT phrase, {second_part_salt_phrase_len} bytes ONLY: ",
                                          "2nd part of SALT")

    user_salt = first_part_salt_phrase + second_part_salt_phrase
    user_salt = user_salt.encode('ascii')
    return user_salt


class Secure:
    # def __init__(self, base64_encode: bool = True) -> None:
    #     self.base64_encode = base64_encode
    #     pass

    def encrypt(self, to_encrypt: str, salt: bytes) -> Tuple[bytes, bytes]:
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

    def decrypt(self, to_decrypt: bytes, salt: bytes, iv: bytes) -> str:
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

    def get_key(self):
        env_names_list = ["PARSE_KEY", "PARSE_SECRET", "PARSE_KEY_IV", "PARSE_SECRET_IV"]
        if not Secure.check_env(env_names_list):
            print('Encrypted API keys not found in environment variables,\nplease create create keys!')
            print()
            Secure.encrypt_keys()
            msg = f'Warning! Keys created please restart application!'
            sys.exit(msg)

        env_values_list = [os.environ.get(name) for name in env_names_list]
        env_values_list = [value.encode('ascii') for value in env_values_list]

        """ Getting encrypted key parts from environment """
        parse_key = env_values_list[0]
        parse_secret = env_values_list[1]
        parse_key_iv = env_values_list[2]
        parse_secret_iv = env_values_list[3]

        """ Getting salt parts """
        secret_phrase: bytes = asking_2components_secret()

        """ Decrypt key and secret """
        key = self.decrypt(parse_key, secret_phrase, parse_key_iv)
        secret = self.decrypt(parse_secret, secret_phrase, parse_secret_iv)
        return key, secret

    @staticmethod
    def encrypt_keys(filename: str = '.env',
                     only_show: bool = True
                     ) -> None:
        """
        Args:
            filename (str):     filename for dot env file
            only_show (bool):   Do not write data to file. Show on screen only
        """
        secret_phrase = asking_2components_secret()
        print()
        key_to_encrypt = getpass.getpass('Enter the API key to encrypt: ')
        secret_to_encrypt = getpass.getpass('Enter the API secret to encrypt: ')

        secure_key = Secure()
        print('Key encryption...')
        key_encrypted_base64, key_iv_base64 = secure_key.encrypt(key_to_encrypt, secret_phrase)
        print('Key decryption...')
        decrypted_key = secure_key.decrypt(key_encrypted_base64, secret_phrase, key_iv_base64)
        if key_to_encrypt == decrypted_key:
            print('Original data match the result!')
        else:
            print('Original data does not match the result\n')
            msg = f'Encrypted & decrypted key: \n{key_to_encrypt}\n{decrypted_key}'
            del key_to_encrypt
            del secret_to_encrypt
            sys.exit(msg)

        print('Secret encryption...')
        secret_encrypted_base64, secret_iv_base64 = secure_key.encrypt(secret_to_encrypt, secret_phrase)

        print('Secret decryption...')
        decrypted_secret = secure_key.decrypt(secret_encrypted_base64, secret_phrase, secret_iv_base64)

        if secret_to_encrypt == decrypted_secret:
            print('Original data match the result!\n')
        else:
            print('Original data does not match the result!\n')
            msg = 'Encrypted & decrypted key: \n{secret_to_encrypt}\n{decrypted_secret}'
            del key_to_encrypt
            del secret_to_encrypt
            sys.exit(msg)

        if only_show:
            print("Encrypted key:", key_encrypted_base64)
            print("Encrypted key iv:", key_iv_base64)

            print(f'Encrypted secret: {secret_encrypted_base64}')
            print(f'Encrypted secret iv: {secret_iv_base64}')
        else:
            sys.stdout = open(filename, 'w')
            sys.stdout.buffer.write((bytes('PARSE_KEY=', 'utf-8')) + key_encrypted_base64 + (bytes('\n', 'utf-8')))
            sys.stdout.buffer.write(
                (bytes('PARSE_SECRET=', 'utf-8')) + secret_encrypted_base64 + (bytes('\n', 'utf-8')))
            sys.stdout.buffer.write((bytes('PARSE_KEY_IV=', 'utf-8')) + key_iv_base64 + (bytes('\n', 'utf-8')))
            sys.stdout.buffer.write((bytes('PARSE_SECRET_IV=', 'utf-8')) + secret_iv_base64 + (bytes('\n', 'utf-8')))
            sys.stdout.close()
        del key_to_encrypt
        del secret_to_encrypt
        pass


if __name__ == '__main__':
    Secure.encrypt_keys(filename='testenv', only_show=False)
