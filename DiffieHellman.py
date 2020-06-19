import hashlib
from binascii import hexlify
from primes import PRIMES

try:
	import ssl
	random_function = ssl.RAND_bytes
	random_provider = "Python SSL"
except (AttributeError, ImportError):
	import OpenSSL
	random_function = OpenSSL.rand.bytes
	random_provider = "OpenSSL"

print(f'Koriscena secure random funkcija je {random_provider}')
print('\n')


class DiffieHellman:
    def __init__(self, rand_function=random_function, generator=2, group=17, key_length=600):

        # definisanje pseudo random generatora
        self.random_function = rand_function

        # definisanje duzine kljuca
        min_key_length = 200
        self.key_length = max(min_key_length, key_length)
    
        # definisanje dh parametra g
        default_generator = 2
        valid_generators = [2,3,5,7]
        if generator not in valid_generators:
            print('bad generator!')
            self.g = default_generator
        else:
            self.g = generator

        # definisanje dh modulusa p
        default_group = 17
        if group in PRIMES:
            self.p = PRIMES[group]
        else:
            print('bad group!')
            self.p = PRIMES[default_group]

        # definisanje dh eksponenta e => private key
        self.__e = self.__generatePrivateKey()
       

    def __generatePrivateKey(self):
        # generise e preko kriptoloski sigurne random funkcije duzine self.key_length koja je gore definisana        
        priv_key = 0
        _bytes = self.key_length // 8 + 8 
        
        try:
            priv_key = int.from_bytes(self.random_function(_bytes), byteorder='big')
        except:
            priv_key = int(OpenSSL.rand.bytes(_bytes).encode('hex'), 16)

        return priv_key

    def __generatePublicKey(self):
        # public key => g**e % p
        return pow(self.g, self.__e, self.p)

    def checkPublicKey(self, other_key):
        # proverava da li je Legendre simbol == 1, po standardu RFC 3526
        if other_key > 2 and other_key < self.p - 1:
            if pow(other_key, (self.p - 1)//2, self.p) == 1:
                return True
        return False

    def __generateSharedSecret(self, other_key):
        if self.checkPublicKey:
            shared_secret = pow(other_key, self.__e, self.p)
            return shared_secret
        else:
            raise Exception('bad public key!')

    
    def generateSharedKey(self, other_key, show_results=True):
        shared_secret = self.__generateSharedSecret(other_key)
        try:
            shared_secret_bytes = shared_secret.to_bytes(
                shared_secret.bit_length() // 8 + 1, byteorder='big'
            )
        except AttributeError:
            shared_secret_bytes = str(shared_secret)

        s = hashlib.sha256()
        s.update(bytes(shared_secret_bytes))
        
        if show_results:
            self.__showResults(shared_secret)

        return s.digest()


    def __showResults(self, shared_secret):
        print(f'Deljena tajna je {shared_secret.bit_length()}-bitni broj: {shared_secret}')


    def getPublicKey(self):
        return self.__generatePublicKey()