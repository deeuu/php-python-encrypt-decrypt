from mycipher import MyCipher

cipher = MyCipher(iv='1234')
secret = 'secret'

print('~~~')
encrypted = cipher.encrypt(secret)
print('encrypted: ', encrypted)
decrypted = cipher.decrypt(encrypted)
print('decrypted: ', decrypted)

print('~~~')
encrypted = cipher.encrypt_includes_iv(secret)
print('Encrypted and shipped with IV: ', encrypted)

cipher = MyCipher(iv=None)
decrypted = cipher.decrypt_includes_iv(encrypted)
print('Decrypted: ', decrypted)
