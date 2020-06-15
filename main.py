from DiffieHellman import DiffieHellman
from binascii import hexlify

a = DiffieHellman()
b = DiffieHellman()

a_key = a.generateSharedKey(b.getPublicKey())
b_key = b.generateSharedKey(a.getPublicKey())

print('\n')
print(f'kljucevi su isti: {a_key == b_key}')
print('\n\n\n')

if a_key == b_key:
    print(hexlify(a_key))
    print(f'duzina kljuca je {len(a_key)} bajta')

