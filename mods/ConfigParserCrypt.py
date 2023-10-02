from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as pad
from cryptography.hazmat.backends import default_backend
import configparser
import os
import json
import base64
import hmac
import hashlib
import logging



class InvalidPassphraseError(Exception):
    pass



class ConfigParserCrypt(configparser.ConfigParser):

    def __init__(self, *args, **kwargs):
        """
            Initialize the ConfigParserCrypt.

            :param passphrase: The passphrase to use for encryption and decryption.
        """
        super().__init__(*args, **kwargs)
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)


    def get_key(self, password, salt):
        """
            Derive a secret key from a given password and salt.

            :param password: The password to derive the key from.
            :param salt: The salt to use for the key derivation.

            :return: The derived key.
        """
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password)
            return key
        except InvalidKey:
            self.logger.error("Error in get_key, invalid passphrase.")
            return "Invalid passphrase."


    def encrypt(self, message, password):
        """
            Encrypt a message using AES-256-CBC with a random salt and IV.

            :param message: The message to encrypt.
            :param password: The password to derive the key from.

            :return: A dictionary containing the encrypted message, salt, IV and HMAC.  If an error occurs, None is returned.
        """
        salt = os.urandom(16)
        key = self.get_key(password, salt)
        if isinstance(key, str):
            return None
        iv = os.urandom(16)
        try:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = pad.PKCS7(128).padder()
            padded_data = padder.update(message) + padder.finalize()
            encrypted_message = encryptor.update(padded_data) + encryptor.finalize()

            # Compute the HMAC
            hmac_object = hmac.new(key, encrypted_message, hashlib.sha256)
            hmac_digest = hmac_object.digest()

            return {"cipher_text": encrypted_message, "salt": salt, "iv": iv, "hmac": hmac_digest}
        except Exception as e:
            self.logger.error(f"Error in encrypt function during encryption: {e}")
            return None


    def decrypt(self, encrypted_dict, password):
        """
            Decrypt a message using AES-256-CBC with a random salt and IV.

            :param encrypted_dict: The dictionary containing the encrypted message, salt, IV and HMAC.
            :param password: The password to derive the key from.

            :return: The decrypted message if the HMAC is valid, None otherwise.
        """
        key = self.get_key(password, encrypted_dict['salt'])
        if isinstance(key, str):
            return None
        try:
            # Check the HMAC
            hmac_object = hmac.new(key, encrypted_dict['cipher_text'], hashlib.sha256)
            hmac_digest = hmac_object.digest()
            if hmac.compare_digest(hmac_digest, encrypted_dict['hmac']):
                cipher = Cipher(algorithms.AES(key), modes.CBC(encrypted_dict['iv']), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_message = decryptor.update(encrypted_dict['cipher_text']) + decryptor.finalize()
                unpadder = pad.PKCS7(128).unpadder()
                unpadded_data = unpadder.update(decrypted_message) + unpadder.finalize()
                return unpadded_data
            else:
                self.logger.warning("HMAC verification failed in decrypt function")
                return None
        except ValueError:
            self.logger.error("Invalid passphrase in decrypt function.")
            return None
        except Exception as e:
            self.logger.error(f"Error during decryption in decrypt function: {e}")
            return None


    def is_valid_ejson(self, value):
        """
            Check if a given string is a valid EJSON string.

            :param value: The string to check.
            :return: True if the string is a valid EJSON string, False otherwise.
        """
        try:
            parsed_json = json.loads(value)
            required_keys = ['cipher_text', 'salt', 'iv', 'hmac']
            for key in required_keys:
                if key not in parsed_json or not isinstance(parsed_json[key], str):
                    return False
                # Check if the value is valid Base64 encoded data
                try:
                    base64.b64decode(parsed_json[key])
                except Exception:
                    return False
            return True
        except json.JSONDecodeError:
            self.logger.error("Error in is_valid_ejson, invalid JSON when parsing EJSON string.")
            return False


    def get_safe_dict(self, encrypted):
        """
            Convert a dictionary containing encrypted data to a dictionary containing Base64 encoded strings.

            :param encrypted: The dictionary containing the encrypted data.
        """
        try:
            return {
                "cipher_text": base64.b64encode(encrypted['cipher_text']).decode('utf-8'),
                "salt": base64.b64encode(encrypted['salt']).decode('utf-8'),
                "iv": base64.b64encode(encrypted['iv']).decode('utf-8'),
                "hmac": base64.b64encode(encrypted['hmac']).decode('utf-8')
            }
        except Exception as e:
            self.logger.error(f"Error in get_safe_dict during conversion to safe dictionary: {e}")
            return None


    def config_read(self, filename):
        """
            Read a configuration file and decrypt all encrypted values.

            :param filename: The name of the configuration file to read.
        """
        try:
            self.config = configparser.ConfigParser(interpolation=None)  # Disable interpolation
            self.config.read(filename)
            needs_encryption = False

            for section in self.config.sections():
                for key, value in self.config[section].items():
                    if key.endswith('_encrypted'):
                        if self.is_valid_ejson(value):
                            encrypted_dict = json.loads(value)
                            encrypted_bytes = {
                                "cipher_text": base64.b64decode(encrypted_dict['cipher_text']),
                                "salt": base64.b64decode(encrypted_dict['salt']),
                                "iv": base64.b64decode(encrypted_dict['iv']),
                                "hmac": base64.b64decode(encrypted_dict['hmac'])
                            }
                            decrypted_value = self.decrypt(encrypted_bytes, os.environ["DRIP_SECRET"].encode('utf-8'))
                            self.config[section][key] = decrypted_value.decode('utf-8')
                        else:
                            needs_encryption = True
                    else:
                        self.config[section][key] = value

            # If the configuration file needs encryption, write it back to disk
            if needs_encryption:
                self.config_write(filename)

            return self.config
        
        except Exception as e:
            self.logger.error(f"Error in config_read during configuration file reading: {e}")
            return None


    def config_write(self, filename):
        """
            Write a configuration file and encrypt all values ending with _encrypted.

            :param filename: The name of the configuration file to write.
        """
        try:
            for section in self.config.sections():
                for key, value in self.config[section].items():
                    if key.endswith('_encrypted'):
                        encrypted_dict = self.encrypt(value.encode('utf-8'), os.environ["DRIP_SECRET"].encode('utf-8'))
                        safe_dict = {
                            "cipher_text": base64.b64encode(encrypted_dict['cipher_text']).decode('utf-8'),
                            "salt": base64.b64encode(encrypted_dict['salt']).decode('utf-8'),
                            "iv": base64.b64encode(encrypted_dict['iv']).decode('utf-8'),
                            "hmac": base64.b64encode(encrypted_dict['hmac']).decode('utf-8')
                        }
                        self.config[section][key] = json.dumps(safe_dict)

            with open(filename, 'w') as configfile:
                self.config.write(configfile)

        except Exception as e:
            self.logger.error(f"Error in config_write during configuration file writing: {e}")
            return None