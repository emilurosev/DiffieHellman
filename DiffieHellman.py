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

print(random_provider)


class DiffieHellman:
    def __init__(self, generator=2, group=17, key_length=540):
        # definisanje duzine kljuca
        min_key_length = 180
        if key_length < min_key_length:
            print('key too small!')
            self.key_length = min_key_length
        else:
            self.key_length = key_length
    
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
        self.__e = self.__generatePrivateKey(key_length)
       

    def __generatePrivateKey(self, bits):
        _rand = 0
        _bytes = bits // 8 + 8

        while _rand.bit_length() < bits:
            try:
                _rand = int.from_bytes(random_function(_bytes), byteorder='big')
            except:
                _rand = int(OpenSSL.rand.byes(_bytes).encode('hex'), 16)

        return _rand

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
        print('Results:')
        print(f'Shared secret is {shared_secret.bit_length()} bits number: {shared_secret}')


    def getPublicKey(self):
        return self.__generatePublicKey()