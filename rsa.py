import random
from Crypto.Util import number


def euclid(a, b):
    """
    Basic Euclidean algorithm for determining the greatest common divisor of two integers
    """
    while b != 0:
        a, b = b, a % b
    return a


def extended_euclid(a, b):
    """
    Extended Euclidean algorithm for determining the multiplicative inverse of two integers
    """
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        q = b // a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
        b, a = a, b % a
    return b, x0, y0


def modular_inverse(a, m):
    """
    Method for determining the modular multiplicative inverse of two integers
    """
    g, x, y = extended_euclid(a, m)
    if g == 1:
        return x % m
    else:
        return None


def is_prime(number):
    """
    Method for determining if an integer is a prime number
    """
    if number > 1:
        for i in range(2, number):
            if number % i == 0:
                return False
        else:
            return True
    else:
        return False


def primes_list():
    """
    Method for determining a list of lower valued prime numbers from 2 to 1000
    """
    primes = []
    for i in range(2, 1001):
        if is_prime(i):
            primes.append(i)
    return primes


def miller_rabin(n, k):
    a = random.randrange(2, (n - 2) - 2)
    x = pow(a, int(k), n)
    if x == 1 or x == n - 1:
        return True
    while k != n - 1:
        x = pow(x, 2, n)
        k *= 2
        if x == 1:
            return False
        elif x == n - 1:
            return True
    return False


def check_prime(number):
    if number < 2:
        return False
    low_primes = primes_list()
    if number in low_primes:
        return True
    for prime in low_primes:
        if number % prime == 0:
            return False
    c = number - 1
    while c % 2 == 0:
        c //= 2
    for i in range(128):
        if not miller_rabin(number, c):
            return False
    return True


def is_coprime(a, b):
    """
    Method for determining if two integers are coprimes
    """
    return euclid(a, b) == 1


def rsa_modulus(p, q):
    """
    Method for generating RSA modulus
    """
    return p * q


def euler(p, q):
    """
    Method for generating Euler's totient
    """
    return (p - 1) * (q - 1)


def generate_e(totient):
    """
    Method for generating public exponent
    """
    e = random.randint(2, totient)
    while not is_coprime(e, totient):
        e = random.randint(2, totient)
    return e


def generate_keys(p, q):
    """
    Method for generating key pairs - public and private keys
    """
    if is_prime(p) and is_prime(q) and p != q:
        modulus = rsa_modulus(p, q)
        totient = euler(p, q)
        e = generate_e(totient)
        private_key = modular_inverse(e, totient)
        return ((e, modulus), (private_key, modulus))


def generate_large_primes_keys(p, q):
    """
    Method for generating keys for larger prime numbers
    """
    if check_prime(p) and check_prime(q) and p != q:
        modulus = rsa_modulus(p, q)
        totient = euler(p, q)
        e = generate_e(totient)
        private_key = modular_inverse(e, totient)
        return ((e, modulus), (private_key, modulus))


def encrypt(public_key, plain_text):
    """
    Method for encrypting messages
    """
    key, modulus = public_key
    return [(ord(char) ** key) % modulus for char in plain_text]


def decrypt(private_key, cipher_text):
    """
    Method for decrypting messages
    """
    key, modulus = private_key
    plain_text = [chr((char ** key) % modulus) for char in cipher_text]
    return ''.join(plain_text)


def compute_rsa():
    """
    Compute key-pairs from user inputted prime numbers, encrypt and decrypt message
    """
    p = int(input('Enter a prime number: '))
    q = int(input('\nEnter a second prime number: '))
    public_key, private_key = generate_keys(p, q)
    print('\nPublic key: ' + str(public_key))
    print('\nPrivate key: ' + str(private_key))
    plain_text = input('\nEnter a message to encrypt with private key: ')
    cipher_text = encrypt(public_key, plain_text)
    print('\nEncrypted message: ' + str(cipher_text))
    plain_text = decrypt(private_key, cipher_text)
    print('\nDecrypted message: ' + str(plain_text))


def generated_rsa():
    """
    Compute keypairs from generated prime numbers of length 1024 bits to generate RSA 2048 bit key, encrypt and decrypt message
    """
    p = number.getPrime(1048)
    q = number.getPrime(1048)
    public_key, private_key = generate_large_primes_keys(p, q)
    print('\nPublic key: ' + str(public_key))
    print('\nPrivate key: ' + str(private_key))
    plain_text = input('\nEnter a message to encrypt with private key: ')
    cipher_text = encrypt(public_key, plain_text)
    print('\nEncrypted message: ' + str(cipher_text))
    plain_text = decrypt(private_key, cipher_text)
    print('\nDecrypted message: ' + str(plain_text))


def menu():
    print('\nChoose an option from the menu below (enter 0 to quit)'
          '\n1. Enter prime numbers to generate key pair (RSA 2048)'
          '\n2. Randomly generate key pair')
    try:
        option = int(input())
        if option == 0:
            print('You have quit the program')
            exit()
        elif option == 1:
            compute_rsa()
        elif option == 2:
            generated_rsa()
        else:
            print(f'You entered {option}, which is not a valid option')
            menu()
            return
    except ValueError as err:
        print('You are supposed to enter a number')
        menu()
        return


if __name__ == "__main__":
    menu()
