#!/usr/bin/env python3
'''
Use fidelio_functions interactively from the command line
'''
import fidelio_functions as ff
import json

PUBLIC_FILE     = 'rsa.json'
PRIVATE_FILE    = 'private.json'


# All global state info goes here
State = {
    'alphabet'      : ff.ASCII_94,
    'password'      : 'FIDELIO',
    'rsa_number'    : None,
    'public_key'    : None,
    'private_key'   : None,
    'key_files'     : False,
    'terminate'     : False }


# User interface

def main_menu(state):
    ''' Display the main menu options '''

    options = """
    What would you like to do?

    [A] select Alphabet

    [C] crack a Caesar cipher
    [D] Decrypt message
    [E] Encrypt message

    [G] Generate rsa number and keys

    [L] Load password, rsa number, and keys
    [M] Modify password

    [P] show Password and private key
    [R] show RSA number and public key
    [S] Save password, rsa number, and keys

    [X] exit
    """
    selection = input(options).lower()
    
    if selection == 'a':
        state = select_alphabet(state)

    elif selection == 'c':
        crack_caesar(state)

    elif selection == 'd':
        decrypt_message(state)

    elif selection == 'e':
        encrypt_message(state)

    elif selection == 'g':
        state = generate_rsa_keys(state)

    elif selection == 'l':
        state = load_password_and_keys(state)

    elif selection == 'm':
        state = modify_password(state)

    elif selection == 'p':
        show_password_and_private_key(state)

    elif selection == 'r':
        show_rsa_public(state)

    elif selection == 's':
        state = save_password_and_keys(state)

    elif selection == 'x':
        state['terminate'] = True
      
    else:
        print( "\nI'm sorry, I don't know what '%s' means." % selection )

    return state


# Alphabet manipulation

def select_alphabet(state):

    options = """
    Choose an alphabet or hit Enter to use default.
    [A] ALL_CAPS:   26 capital letters and nothing else
    [B] CAPS_PLUS:  capital letters, digits, some punctuation
    [C] ASCII_94:   ASCII chars 32 through 125
    """
    selection = input(options).lower()
    print( )

    if selection == 'a':
        print( "Using %s-char alphabet 'ALL_CAPS'" % len(ff.ALL_CAPS) )
        state['alphabet'] = ff.ALL_CAPS

    elif selection == 'b':
        print( "Using %s-char alphabet 'CAPS_PLUS'" % len(ff.CAPS_PLUS) )
        state['alphabet'] = ff.CAPS_PLUS

    else:
        print( "Using default 94-char alphabet 'ASCII_94'" )
        state['alphabet'] = ff.ASCII_94

    return state


# Cracking

def crack_caesar(state):

    alphabet    = state['alphabet']
    ciphertext  = input( "\nEnter encrypted message\n" )

    print( )
    print( "Showing all possible Caesar decryptions..." )
    for k in range(len(alphabet)):
        guesstext = ff.caesar(ciphertext,k,alphabet)
        print( )
        print( str(k) + '\t' + guesstext )


# Encryption and decryption

def input_message():

    options = '''
    Choose encryption scheme:
    [C] Caesar
    [D] Dodgson
    [R] RSA
    '''
    scheme = input(options).lower()
    
    if scheme not in ['c','d','r']:
        print( "\n*** Unknown method '%s'\n" % scheme )
        scheme  = None
        msg     = None

    else:
        msg = input("\nEnter message:\n")

    return scheme, msg

def decrypt_message(state):

    scheme, msg  = input_message()

    if scheme == 'c':

        shift = input( "Enter shift amount (or hit Enter to use default)\n" )
        if not shift:
            shift = -3

        decipher = ff.caesar(msg,-int(shift),state['alphabet'])
        print("\nCaesar decription with shift %s:" % shift )
        print(decipher)

    elif scheme == 'd':

        decipher = ff.dodgson(msg,state['password'],state['alphabet'],decrypt=True)
        print("\nDodgson decryption:")
        print(decipher)

    elif scheme == 'r':

        rsa_number  = state['rsa_number']
        private_key = state['private_key']

        if rsa_number & private_key:
            decipher = ff.rsa_decrypt(msg,rsa_number,private_key,state['alphabet'])
            print("\nRSA decryption:")
            print(decipher)

        else:
            print( "\n*** Need to load RSA number and private key!" )

def encrypt_message(state):

    scheme, msg = input_message()

    if scheme == 'c':

        shift = input( "Enter shift amount (or hit Enter to use default)\n" )
        if not shift:
            shift = -3

        cipher = ff.caesar(msg,int(shift),state['alphabet'])
        print("\nCaesar encryption:")
        print(cipher)

    elif scheme == 'd':

        cipher = ff.dodgson(msg,state['password'],state['alphabet'])
        print("\nDodgson encryption:")
        print(cipher)

    elif scheme == 'r':

        rsa_number = input( "Enter recipient's RSA number. (Hit Enter to use yours)\n" )
        public_key = input( "Enter recipient's public key. (Hit Enter to use yours)\n" )

        if not rsa_number:
            rsa_number = state['rsa_number']
        if not public_key:
            public_key = state['public_key']

        cipher = ff.rsa_encrypt(msg,int(rsa_number),int(public_key),state['alphabet'])
        print("\nRSA encryption:")
        print(cipher)


# Password and key management

def generate_rsa_keys(state):

    print( )
    print( "Generating RSA keys..." )
    state['rsa_number'], state['public_key'], state['private_key'] = ff.generate_keys()

    show_rsa_public(state)

    return state

def load_password_and_keys(state):

    print( )

    print( "Loading RSA number and public key from %s" % PUBLIC_FILE )
    with open(PUBLIC_FILE,'r') as f:
        public = json.load(f)
        for k in public.keys():
            state[k] = public[k]

    print( "Loading password and privat key from %s" % PRIVATE_FILE )
    with open(PRIVATE_FILE,'r') as f:
        private = json.load(f)
        for k in private.keys():
            state[k] = private[k]

    return state

def modify_password(state):

    password = str(input("\nEnter a password for polyalphabetic encryption.\n"))
    passcode = ff.text_to_digits(password,state['alphabet'])

    if len(passcode) != len(password):
        print("\n*** Warning: password contains characters not available in selected alphabet!\n")
    else:
        print("Password accepted")

    state['password'] = password

    return state

    print( cipher )

def show_password_and_private_key(state):

    print( )
    print( "Password:       %s" % state['password'] )
    print( "Private key:    %s" % state['private_key'] )

def show_rsa_public(state):

    print( )
    print( "RSA number: %s" % state['rsa_number'] )
    print( "Public key: %s" % state['public_key'] )

def save_password_and_keys(state):

    print( )

    print( "Saving RSA number and public key to %s" % PUBLIC_FILE )
    public = { k:state[k] for k in ['rsa_number','public_key'] }    
    with open(PUBLIC_FILE,'w') as f:
        json.dump(public,f)

    print( "Saving password and private key to %s" % PRIVATE_FILE )
    private = { k:state[k] for k in ['private_key','password'] }
    with open(PRIVATE_FILE,'w') as f:
        json.dump(private,f)

    state['key_files'] = True

    return state



# Make script executable

if __name__=='__main__':

    # Check for saved keys on startup
    try:
        State = load_password_and_keys(State)
        State['key_files'] = True
    except:
        State['key_files'] = False

    # Run main_menu() until user quits
    while not State['terminate']:
        State = main_menu(State)



