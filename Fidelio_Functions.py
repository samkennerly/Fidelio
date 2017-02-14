'''
Import this module into fidelio.py
'''
import random


# Alphabet definitions go here.
# Each alphabet is a tuple for mapping int -> char.

# Classic encryption (with no whitespace!)
ALPHABET26 = ('A','B','C','D','E','F','G','H','I',      \
            'J','K','L','M','N','O','P','Q','R','S',    \
            'T','U','V','W','X','Y','Z')

# This should be enough for basic messaging
ALPHABET42 = ('0','1','2','3','4','5','6','7','8','9',  \
            ' ','A','B','C','D','E','F','G','H','I',    \
            'J','K','L','M','N','O','P','Q','R','S',    \
            'T','U','V','W','X','Y','Z',',','.','?',    \
            '!',' ')

# ASCII chars 32-127 (0-31 are special system commands)
ALPHABET96 = tuple([ chr(i) for i in range(32,128) ])

# Where did we save the list of prime numbers?
PRIMES_FILE     = 'Primes.txt'

# How many of the first prime numbers are off-limits for being too small?
DISCARD_PRIMES  = 1000


# Functions for mapping text <-> [list of integers]

def char_to_num(alphabet):
    ''' Make a dictionary with chars as keys and ints as values '''

    char_dict = dict.fromkeys(alphabet)
    for k in range(len(alphabet)):
        char_dict[ alphabet[k] ] = k

    return char_dict

def text_to_digits(text,alphabet=ALPHABET96):
    '''
    Transform a string into a list of ints.
    Caution: characters not in the alphabet will be dropped!
    '''

    char_dict   = char_to_num(alphabet)
    digits      = [ char_dict[x] for x in text if x in char_dict.keys() ]

    return digits

def digits_to_text(digits,alphabet=ALPHABET96):
    ''' Transform a list of ints into a string '''

    too_big = len(alphabet)
    text    = [ alphabet[x] for x in digits if x < too_big ]
    text    = "".join(text)

    return text



# Simple encryption functions

def caesar(plain_text,shift=3,decrypt=False,alphabet=ALPHABET96):
    '''
    Caesar cipher: shift all characters by the same amount
    using modular arithmetic. Default is classic Caesar.
    Set shift=13 for ROT13 scheme, which is its own inverse.
    '''
    
    if decrypt:
        shift *= -1

    digits      = text_to_digits(plain_text,alphabet)
    cipher      = [ (x+shift) % len(alphabet) for x in digits ]
    cipher_text = digits_to_text(cipher,alphabet)

    return cipher_text

def dodgson(plain_text,password,decrypt=False,alphabet=ALPHABET96):

    digits      = text_to_digits(plain_text,alphabet)
    passcode    = text_to_digits(password,alphabet)

    if decrypt:
        passcode = [ -x for x in passcode ]

    # Make a passcode which is the same length as [digits].
    # Repeat the passcode as many times as necessary.
    nDigits     = len(digits)
    full_code   = passcode.copy()
    for k in range(0,nDigits,len(passcode)):
        full_code.extend(passcode)
    full_code   = full_code[0:nDigits]

    # Shift each digit by the corresponding amount in [full_code]
    cipher = [ (digits[k]+full_code[k]) % len(alphabet) for k in range(nDigits) ]

    cipher_text = digits_to_text(cipher,alphabet)

    return cipher_text



# Functions for packing and padding a list of 2-digit ints

def packetize(digits):
    '''
    Convert a list of 1- and 2-digit numbers into a shorter list of 8-digit numbers.
    Pad the last packet with random digits if needed.
    Last digit of last packet counts how much padding was used (including itself).
    NOTE:   Converting int -> string -> int is not very efficient.
            This is an educational program, not a professional crypto tool!
    '''

    # Combine list of integers into one big string of digits
    one_big_string  = [ str(x).zfill(2) for x in digits ]
    one_big_string  = ''.join(one_big_string)

    # Break the big string into packets
    steps   = range(0,len(one_big_string),8)
    packets = [ one_big_string[n:n+8] for n in steps ]

    # Add padding
    def pad_me(packet):

        nDigits     = 8 - len(packet)
        pads        = [ random.randint(0,9) for n in range(nDigits) ]
        pads[-1]    = nDigits
        pads        = ''.join([ str(x) for x in pads ])

        return packet + pads

    # If the last packet is exactly 8 digits, then append another packet.
    # This last packet will be all pads.
    if len(packets[-1]) == 8:
        packets.append('')

    packets[-1] = pad_me(packets[-1])

    # Convert back to integers after we're done playing with digits
    packets = [ int(x) for x in packets ]

    return packets

def unpacketize(packets):
    ''' Undo packetize() function '''

    # How much padding was added to the last packet?
    nPads = packets[-1] % 10

    # Convert each packet to a string of digits
    packets = [ str(x).zfill(8) for x in packets ]

    # Remove any digits that were actually random
    if nPads == 8:
        del packets[-1]
    else:
        packets[-1] = packets[-1][0:8-nPads]

    # Prepare to chop each packet into 2-digit numbers
    def chop_packet(packet):
    
        steps   = range(0,len(packet),2)
        pieces  = [ int(packet[n:n+2]) for n in steps ]

        return pieces

    # Dynamically re-sizing a list is slow, but let's do it anyway
    digits = []
    for x in packets:
        digits += chop_packet(x)

    return digits


# Maths for RSA

def gcd(x,y):
    '''
    Find the greatest common denominator of two positive ints.
    (This is a recursive version of the Euclidean Algorithm.)
    '''
    if y == 0:
        return x
    return gcd(y,x%y)

def gcd_factor(e,n,verbose=False):
    '''
    Given two positive integers e and n with e < n, the 
    Extended Euclidean Algorithm finds x,y such that
    nx + ey = gcd(e,n). This is a limited version which finds
    gcd(e,n) and x, but doesn't bother finding y.
    '''
    
    assert e < n, "First arg should be smaller than second arg!"
    
    r = (n,e)
    x = (0,1)
    while r[1] > 0:
        if verbose:
            print( r[0], x[0] )
        quotient = r[0] // r[1]
        next_r = r[0] - quotient * r[1]
        next_x = x[0] - quotient * x[1]
        r = ( r[1], next_r )
        x = ( x[1], next_x )
        
    # We want the results just before the last row
    gcd = r[0]
    x   = x[0]
    
    # If x is negative, then replace it with a positive
    # number which is equivalent to x (mod n).
    if x < 0:
        x = x % n
        
    return gcd, x

def test_gcd_factor(e,n,verbose=False):
    '''
    It's remarkably easy to screw up the Extended Euclidean Algorithm.
    Use this to verify that gcd_factor() does what I think it does.
    '''
    
    gcd_test, x_test = gcd_factor(e,n)
        
    # Did we get the correct GCD?
    gcd_true = gcd(n,e)
    if gcd_test != gcd_true :
        print( "GCD of %s and %s is %s, not %s" % (e,n,gcd_true,gcd_test) )
        return False
    
    # Does (e * x) % n = gcd(e,n) ?
    product_test = (e*x_test) % n
    if product_test != gcd_true:
        print( "%s times %s mod %s is %s, not %s" % (e,x_test,n,product_test,gcd_true) )
        return False
    
    return True



# RSA functions

def load_primes(too_small=None,too_large=None):
    '''
    Load prime numbers from a text file.
    Discard numbers which are too large or too small.
    '''

    print( "Loading prime numbers from %s" % PRIMES_FILE )
    with open(PRIMES_FILE,'r') as f:
        primes = f.read()

    # Parse the text file
    primes = [ int(x) for x in primes.split(' ') ]

    # Only use primes within selected range
    if too_small is not None:
        primes = [ x for x in primes if x > too_small ]
    if too_large is not None:
        primes = [ x for x in primes if x < too_large ]

    return primes

def choose_rsa_number(primes,verbose=False):
    ''' Generate an RSA number and find its Euler totient '''

    [p,q]   = random.sample(primes,2)
    n       = p * q
    totient = (p-1) * (q-1)

    if verbose:
        print( "RSA number is %s * %s = %s" % (p,q,n) )
        print( "Euler totient is %s" % totient )

    return n, totient

def choose_public_key(primes,totient,verbose=False):
    ''' Choose a public key suitable for our RSA number and totient '''

    assert primes[0] < totient, "Need prime numbers less than totient!"

    # Use rejection sampling: choose random samples until we get a good one
    for n in range(1000):
        
        [public_key] = random.sample(primes,1)

        if verbose:
            print( "Testing public key %s" % public_key )

        if (public_key >= totient) | (totient % public_key ==0):
            continue

        else:
            print( "Public key is %s" % public_key )
            return public_key

    # Hopefully we never get this far
    raise RuntimeError("Gave up trying to find a good public key!")

def find_private_key(public_key,totient,verbose=False):
    '''
    Find the multiplicative inverse (mod totient) of the public key.
    This inverse does not exist if public, totient are not relatively prime!
    Throw an exception if that happens.
    '''

    gcd, private_key = gcd_factor(public_key,totient)
    assert (gcd == 1), "GCD of public key %s and totient %s is %s, not 1" % (public_key,totient,gcd)

    if verbose:
        print( "Private key is %s" % private_key )

    return private_key

def generate_keys(too_small=10000,too_large=100000,verbose=False):
    ''' Generate RSA number, public key, and private key '''

    primes      = load_primes(too_small,too_large)
    n, totient  = choose_rsa_number(primes,verbose)
    public_key  = choose_public_key(primes,totient,verbose)
    private_key = find_private_key(public_key,totient,verbose)

    return n, public_key, private_key



























def generatekey():
    '''
    Generate an RSA number, totient, public and private key
    '''

    primesfile = open("10000primes.txt", "r")
    primeslist = primesfile.read().split()
    prime0 = int(primeslist[random.randint(5000,len(primeslist))])  # The first 5000 primes are not used.   
    prime1 = int(prime0)

    while prime1 == prime0 :        # This loop ensures that the two primes are not the same.
        prime1 = int(primeslist[random.randint(5000,len(primeslist))])
    totient = (prime0 - 1) * (prime1 - 1)
    rsan = prime0 * prime1
    
    # Choose a (prime) public key that is large but less than the totient.
    publickey = 10968163441         # This is the 10000th prime squared; totient is less than this
    while publickey > totient:
        publickey = int(primeslist[random.randint(5000,len(primeslist))])   # First 5000 primes not used.   
    
    # <findinverse> finds the multiplicative inverse of the public key (mod totient).
    privatekey = findinverse(publickey, totient)
    RSAkeylist = [prime0, prime1, rsan, publickey, privatekey, totient]

    return RSAkeylist

def RSAencrypt(packetlist, rsan, publickey):
    '''
    Encrypt a list of long ints using the RSA scheme.
    '''

    cipherlist = []
    cipherpacket = ""
    for i in range(len(packetlist)) :
        cipherlist.append( modexp( packetlist[i], publickey, rsan ) )

    return cipherlist

def RSAdecrypt(cipherlist, rsan, privatekey):
    ''' Decrypt result of RSAencrypt '''

    decryptedlist = []
    for i in range(len(cipherlist)) :
        decryptedlist.append( modexp( cipherlist[i] , privatekey , rsan ) )

    return decryptedlist

def modexp(a, n, m):
    '''
    Fast modular exponentiation of large numbers
    Author: Wojtek Jamrozy (www.wojtekrj.net)
    '''

    bits = []
    while n:
        bits.append(n%2)
        n /= 2
    solution = 1
    bits.reverse()
    for x in bits:
        solution = (solution*solution)%m
        if x:
            solution = (solution*a)%m

    return solution





