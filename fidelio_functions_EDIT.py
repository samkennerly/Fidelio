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
            '!','/')

# Default alphabet is ASCII chars 32 through 125
ALPHABET94 = tuple([ chr(i) for i in range(32,126) ])

# Where did we save the list of prime numbers?
PRIMES_FILE     = 'Primes.txt'

# How many of the first prime numbers are off-limits for being too small?
DISCARD_PRIMES  = 1000



# Simple encryption functions

def caesar(plain_text,shift=-3,decrypt=False,alphabet=ALPHABET94):
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

def dodgson(plain_text,password,decrypt=False,alphabet=ALPHABET94):

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



# RSA encryption functions

def generate_keys(too_small=10000,too_large=100000,verbose=False):
    ''' Generate RSA number, public key, and private key '''

    primes      = load_primes(too_small,too_large)
    n, totient  = choose_rsa_number(primes,verbose)
    public_key  = choose_public_key(primes,totient,verbose)
    private_key = find_private_key(public_key,totient,verbose)

    return n, public_key, private_key

def rsa_encrypt(message,n,public_key,alphabet=ALPHABET94):
    ''' Encrypt a message using RSA '''

    digits  = packetize(text_to_digits(message,alphabet))
    cipher  = [ pow(m,public_key,n) for m in digits ]

    return cipher

def rsa_decrypt(cipher,n,private_key,alphabet=ALPHABET94):
    ''' Decrypt an RSA cipher '''

    decipher    = [ pow(c,private_key,n) for c in cipher ]
    plaintext   = digits_to_text(unpacketize(decipher),alphabet)

    return plaintext



# Functions for mapping text <-> [list of integers]

def char_to_num(alphabet):
    ''' Make a dictionary with chars as keys and ints as values '''

    char_dict = dict.fromkeys(alphabet)
    for k in range(len(alphabet)):
        char_dict[ alphabet[k] ] = k

    return char_dict

def text_to_digits(text,alphabet=ALPHABET94):
    '''
    Transform a string into a list of ints.
    Caution: characters not in the alphabet will be dropped!
    '''

    char_dict   = char_to_num(alphabet)
    digits      = [ char_dict[x] for x in text if x in char_dict.keys() ]

    return digits

def digits_to_text(digits,alphabet=ALPHABET94):
    ''' Transform a list of ints into a string '''

    too_big = len(alphabet)
    text    = [ alphabet[x] for x in digits if x < too_big ]
    text    = "".join(text)

    return text

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
    '''
    Find the multiplicative inverse (mod totient) of the public key.
    This inverse does not exist if public, totient are not relatively prime!
    Throw an exception if that happens.
    '''

    gcd, private_key = gcd_and_inverse(public_key,totient)
    assert (gcd == 1), "GCD of public key %s and totient %s is %s, not 1" % (public_key,totient,gcd)

    if verbose:
        print( "Private key is %s" % private_key )

    return private_key



# Maths for RSA

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


