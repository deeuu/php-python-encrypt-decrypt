from mycipher import MyCipher

cipher = MyCipher('1234', 'my_key')
secret = 'secret'

print('~~~')
encrypted = cipher.encrypt(secret)
print('encrypted: ', encrypted)
decrypted = cipher.decrypt(encrypted)
print('decrypted: ', decrypted)

print('~~~')
cipher = MyCipher()
encrypted = cipher.encrypt_includes_iv(secret)
print('Encrypted msg, shipped with IV: ', encrypted)

decrypted = cipher.decrypt_includes_iv(encrypted)
print('Decrypted: ', decrypted)
