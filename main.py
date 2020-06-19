from DiffieHellman import DiffieHellman
from binascii import hexlify

if __name__ == "__main__":

    alisa = DiffieHellman()
    bob = DiffieHellman()

    print('Alisa:')
    alisa_key = alisa.generateSharedKey(bob.getPublicKey(), show_results=True)
    print('\n')
    print('Bob:')
    bob_key = bob.generateSharedKey(alisa.getPublicKey(), show_results=True)

    print('\n')
    print(f'Kljucevi su isti: {alisa_key == bob_key}')
    print('\n')

    if alisa_key == bob_key:
        print(f'Kljuc koji se moze koristiti za AES sifru: {hexlify(alisa_key)}')
        print(f'Duzina kljuca je {len(alisa_key)*8} bitova')