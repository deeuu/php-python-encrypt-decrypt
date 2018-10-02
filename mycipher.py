#encoding: UTF-8

# Python Class for AES encryption
"""
    https://github.com/arajapandi/php-python-encrypt-decrypt
    Example Usage
    enc_str = cipher.encrypt('secret')
    enc_str = cipher.decrypt(enc_str)
    print enc_str; #secret
"""

from Crypto.Cipher import AES
from Crypto import Random
import base64
import hashlib
import sys


class MyCipher:
    #Default Key for encryption
    rawkey      = 'asdfa923aksadsYahoasdw998sdsads'
    method      = AES.MODE_CFB
    blocksize   = 32  # 16, 32..etc
    padwith     = '`' # padding value for string  
    
    #lambda function for padding
    pad         = lambda self, s: s + (self.blocksize - len(s) % self.blocksize) * self.padwith
    
    """
    construct for cipher class - get, set key and iv
    """
    def __init__(self, iv='', key='', hash_iv=True, hash_key=True):
        
        self.input_iv = iv
        self.input_key = key

        if not key:
            key = self.rawkey

        if hash_key:
            self.key = (
                hashlib.sha256(key.encode('utf-8'))
                .hexdigest()[:32]
                .encode('utf-8')
            )

        if not iv:
            self.iv = Random.get_random_bytes(16)
        else:
            self.iv = iv.encode('utf-8')

        if hash_iv:
            self.iv = hashlib.sha256(self.iv).hexdigest()[:16].encode('utf-8')

    def get_cipher(self):
        return AES.new(self.key,
                       self.method,
                       iv=self.iv,
                       segment_size=128)
    
    """
    Encrypt given string using AES encryption standard
    """
    def encrypt(self, raw):
        cipher = self.get_cipher()
        return base64.b64encode(cipher.encrypt(self.pad(raw).encode('utf-8')))
    
    """
    Decrypt given string using AES standard
    """
    def decrypt(self, encrypted):
        encrypted = base64.b64decode(encrypted)
        cipher = self.get_cipher()
        return cipher.decrypt(encrypted).rstrip(self.padwith.encode('utf-8'))

    '''
    Encrypt given string using AES encryption standard, but prepends
    the iv and then encodes the composite bytes object
    '''
    def encrypt_includes_iv(self, raw):

        cipher = self.get_cipher()
        out = base64.b64encode(self.iv +
                               cipher.encrypt(self.pad(raw).encode('utf-8')))
        return out

    '''
    Decrypt string using AES encryption standard, but expects the first 16
    bytes to be the iv_hash
    '''
    def decrypt_includes_iv(self, encrypted):
        encrypted = base64.b64decode(encrypted)
        iv_hash, encrypted = encrypted[:16], encrypted[16:]

        cipher = AES.new(self.key,
                         self.method,
                         iv_hash,
                         segment_size=128)

        return cipher.decrypt(encrypted).rstrip(self.padwith.encode('utf-8'))
