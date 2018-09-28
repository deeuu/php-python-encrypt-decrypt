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
    def __init__(self, iv, key=''):
        
        if(not key): 
            key = self.rawkey
            
        self.key    = key
        self.iv     = iv
    
    """
    get hased key - if key is not set on init, then default key wil be used
    """
    def getKEY(self):
        if(not self.key):
            sys.exit()
            
        return hashlib.sha256(self.key.encode('utf-8')).hexdigest()[:32]
    
    """
    get hashed IV value - if no IV values then it throw error
    """
    def getIV(self):
        if(not self.iv):
            sys.exit()
            
        iv = hashlib.sha256(self.iv.encode('utf-8')).hexdigest()[:16]
        return iv

    def get_cipher(self):
        return AES.new(self.getKEY().encode("utf-8"),
                       self.method,
                       self.getIV().encode("utf-8"),
                       segment_size=128)
    
    """
    Encrypt given string using AES encryption standard
    """
    def encrypt(self, raw):
        cipher = self.get_cipher()
        return base64.b64encode(cipher.encrypt(self.pad(raw).encode("utf-8")))
    
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
        out = base64.b64encode(self.getIV().encode('utf-8') +
                               cipher.encrypt(self.pad(raw).encode('utf-8')))
        return out

    '''
    Decrypt string using AES encryption standard, but expects the first 16
    bytes to be the iv_hash
    '''
    def decrypt_includes_iv(self, encrypted):
        encrypted = base64.b64decode(encrypted)
        iv_hash, encrypted = encrypted[:16], encrypted[16:]

        cipher = AES.new(self.getKEY().encode("utf-8"),
                         self.method,
                         iv_hash,
                         segment_size=128)

        return cipher.decrypt(encrypted).rstrip(self.padwith.encode('utf-8'))


if __name__ == '__main__':

    cipher = MyCipher('1234', '1234')
    encrypted = cipher.encrypt('hello')
    decrypted = cipher.decrypt(encrypted)
    print(decrypted)

    encrypted = cipher.encrypt_includes_iv('hello')

    cipher = MyCipher('', '1234')
    decrypted = cipher.decrypt_includes_iv(encrypted)
    print(decrypted)
