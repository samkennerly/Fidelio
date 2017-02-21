'''
Functions for encryption and decryption
'''
import random


# Alphabet definitions are stored as global variables.
# Each alphabet is a tuple for mapping int -> char.

# Classic 26-character encryption (no whitespace!)
ALL_CAPS = ('A','B','C','D','E','F','G','H','I',      \
            'J','K','L','M','N','O','P','Q','R','S',    \
            'T','U','V','W','X','Y','Z')

# Capital letters plus digits and some punctuation
CAPS_PLUS = ('0','1','2','3','4','5','6','7','8','9',  \
            ' ','A','B','C','D','E','F','G','H','I',    \
            'J','K','L','M','N','O','P','Q','R','S',    \
            'T','U','V','W','X','Y','Z',',','.','?',    \
            '!','/')

# Default alphabet is ASCII chars 32 through 126, plus a few extras
DEFAULT_100 = [ chr(i) for i in range(32,127) ]
DEFAULT_100 += ['∃','∀','∑','¬','∞']
DEFAULT_100 = tuple(DEFAULT_100)

# Where did we save the list of prime numbers?
PRIMES_FILE     = 'Primes.txt'



# Simple encryption functions

def caesar(plain_text,shift=-3,alphabet=DEFAULT_100,decrypt=False):
    '''
    Caesar cipher: shift all characters by the same amount
    using modular arithmetic. Default is classic Caesar.
    Set shift=13 for ROT13 scheme, which is its own inverse.
    '''
    
    if decrypt:
        shift *= -1

    ints        = text_to_ints(plain_text,alphabet)
    cipher      = [ (x+shift) % len(alphabet) for x in ints ]
    cipher_text = ints_to_text(cipher,alphabet)

    return cipher_text

def dodgson(plain_text,password,alphabet=DEFAULT_100,decrypt=False):
    '''
    Polyalphabetic cipher: shift characters by varying amounts
    based on a shared-key password. Password must use characters which
    are valid in the selected alphabet.
    '''

    ints        = text_to_ints(plain_text,alphabet)
    passcode    = text_to_ints(password,alphabet)

    if decrypt:
        passcode = [ -x for x in passcode ]

    # Make a passcode which is the same length as [ints].
    # Repeat the passcode as many times as necessary.
    nInts       = len(ints)
    full_code   = passcode.copy()
    for k in range(0,nInts,len(passcode)):
        full_code.extend(passcode)
    full_code   = full_code[0:nInts]

    # Shift each digit by the corresponding amount in [full_code]
    cipher = [ (ints[k]+full_code[k]) % len(alphabet) for k in range(nInts) ]

    cipher_text = ints_to_text(cipher,alphabet)

    return cipher_text


# RSA encryption functions

def generate_keys(verbose=False):
    ''' Generate RSA number, public key, and private key '''

    primes      = load_primes(10000,100000)
    n, totient  = choose_rsa_number(primes,verbose)
    public_key  = choose_public_key(primes,totient,verbose)
    private_key = find_private_key(public_key,totient,verbose)

    return n, public_key, private_key

def rsa_encrypt(message,n,public_key):
    ''' Encrypt a message using RSA scheme '''

    packets     = packetize(text_to_ints(message))
    cipher      = [ pow(m,public_key,n) for m in packets ]

    # Convert to space-separated string so users can copypaste
    cipher  = ' '.join([ str(x) for x in cipher ])

    return cipher

def rsa_decrypt(ciphertext,n,private_key):
    ''' Undo rsa_encrypt() '''

    # Convert from space-separated string to list of ints
    cipher      = [ int(x) for x in ciphertext.strip().split(' ') ]

    decipher    = [ pow(c,private_key,n) for c in cipher ]
    plaintext   = ints_to_text(unpacketize(decipher))

    return plaintext


# RSA utility functions

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
        print( "Euler totient is %s * %s = %s" % (p-1,q-1,totient) )

    return n, totient

def choose_public_key(primes,totient,verbose=False):
    ''' Choose a public key suitable for our RSA number and totient '''

    assert primes[0] < totient, "Need prime numbers less than totient!"

    # Use rejection sampling: choose random samples until we get a good one
    for n in range(1000):
        
        [public_key] = random.sample(primes,1)

        if (public_key >= totient) | (totient % public_key ==0):
            continue

        else:
            if verbose:
                print( "Public key is %s" % public_key )
            return public_key

    # Hopefully we never get this far
    raise RuntimeError("Gave up trying to find a good public key!")

def find_private_key(public_key,totient,verbose=False):
    ''' Find the multiplicative inverse (mod totient) of the public key '''

    gcd, private_key = gcd_and_inverse(public_key,totient)
    assert (gcd == 1), "GCD of public key %s and totient %s is %s, not 1" % (public_key,totient,gcd)

    if verbose:
        print( "Private key is %s" % private_key )

    return private_key


# Maths for RSA key generation

def gcd(x,y):
    '''
    Find the greatest common denominator of two positive ints.
    (This is a recursive version of the Euclidean Algorithm.)
    '''
    if y == 0:
        return x
    return gcd(y,x%y)

def gcd_and_inverse(k,n,verbose=False):
    '''
    Given two positive integers k and n with k < n, the 
    Extended Euclidean Algorithm finds x,y such that
    nx + ky = gcd(k,n). This is a limited version which finds
    gcd(k,n) and x, but it doesn't bother finding y.
    '''
    
    assert k < n, "First arg should be smaller than second arg!"
    
    r = (n,k)
    x = (0,1)
    while r[1] > 0:
        if verbose:
            print( r[0], x[0] )
        quotient = r[0] // r[1]
        next_r = r[0] - quotient * r[1]
        next_x = x[0] - quotient * x[1]
        r = ( r[1], next_r )
        x = ( x[1], next_x )
        
    # We want the results just before last
    gcd = r[0]
    x   = x[0]
    
    # If x is negative, then replace it with a positive
    # number which is equivalent to x (mod n).
    if x < 0:
        x = x % n
        
    return gcd, x

def test_gcd_and_inverse(k,n,verbose=False):
    '''
    It's easy to implement the Extended Euclidean Algorithm incorrectly.
    Use this to verify that gcd_and_inverse() does what I think it does.
    '''
    
    gcd_test, x_test = gcd_and_inverse(k,n)
        
    # Did we get the correct GCD?
    gcd_true = gcd(n,k)
    if gcd_test != gcd_true :
        print( "GCD of %s and %s is %s, not %s" % (k,n,gcd_true,gcd_test) )
        return False
    
    # Does (e * x) % n = gcd(e,n) ?
    product_test = (k*x_test) % n
    if product_test != gcd_true:
        print( "%s times %s mod %s is %s, not %s" % (k,x_test,n,product_test,gcd_true) )
        return False
    
    return True


# Functions for mapping text <-> [list of integers]

def char_to_num(alphabet):
    ''' Make a dictionary with chars as keys and ints as values '''

    char_dict = dict.fromkeys(alphabet)
    for k in range(len(alphabet)):
        char_dict[ alphabet[k] ] = k

    return char_dict

def text_to_ints(text,alphabet=DEFAULT_100):
    '''
    Transform a string into a list of ints.
    Caution: characters not in the alphabet will be dropped!
    '''

    char_dict   = char_to_num(alphabet)
    ints        = [ char_dict[x] for x in text if x in char_dict.keys() ]

    return ints

def ints_to_text(ints,alphabet=DEFAULT_100):
    ''' Transform a list of ints into a string '''

    too_big     = len(alphabet)
    text        = [ alphabet[x] for x in ints if x < too_big ]
    text        = "".join(text)

    return text

def pad(ints):
    '''
    Pad list of 2-digit ints list with some extra numbers.
    Length of result will be a multiple of 4.
    Last entry is how much padding to discard later.
    '''

    nPad        = 4 - ( len(ints) % 4 )
    pads        = [ random.randint(0,99) for j in range(nPad) ]
    pads[-1]    = nPad

    return ints + pads

def unpad(ints):
    ''' Undo pad() function '''

    return ints[0:-ints[-1]]

def packetize(ints):
    ''' Convert a list of ints < 100 into a shorter list of ints < 1e8 '''

    # Pad the list of ints 
    packets = pad(ints)

    def bunch4(chunk):
        return 1000000*chunk[0] + 10000*chunk[1] + 100*chunk[2] + chunk[3]
    packets = [ bunch4(packets[j:j+4]) for j in range(0,len(ints),4) ]

    return packets

def unpacketize(packets):
    ''' Undo packetize() function '''

    def unbunch4(packet):

        chunk       = [ 0,0,0,0 ]
        chunk[0]    = packet // 1000000
        chunk[1]    = (packet%1000000) // 10000
        chunk[2]    = (packet%10000) // 100
        chunk[3]    = packet % 100
        
        return chunk

    nPackets    = len(packets)
    ints        = [ 0 for x in range(4*nPackets) ]
    for j in range(nPackets):
        start = 4 * j
        ints[start:start+4] = unbunch4(packets[j])

    # Remember to remove padding
    ints = unpad(ints)

    return ints



