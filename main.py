from DiffieHellman import DiffieHellman
from binascii import hexlify

if __name__ == "__main__":

    a = DiffieHellman(name='Alisa')
    b = DiffieHellman(name='Bob')

    a_key = a.generateSharedKey(b.getPublicKey())
    print('\n')
    b_key = b.generateSharedKey(a.getPublicKey())

    print('\n')
    print(f'Kljucevi su isti: {a_key == b_key}')
    print('\n')

    if a_key == b_key:
        print(f'Kljuc koji se moze koristiti za AES sifru: {hexlify(a_key)}')
        print(f'Duzina kljuca je {len(a_key)*8} bitova')