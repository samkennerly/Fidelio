#	Fidelio is a toy program for teaching various encryption and decryption schemes.
#
#	 Copyright 2009 Sam Kennerly
#
#    This file is part of Fidelio.
#
#    Fidelio is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Fidelio is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

# -------------------------- FUNCTIONS ------------------------------------

import random

# This function translates a text message into a list of ints using a dictionary. (see Global Variables.)
# Any char NOT stored in the dictionary is assigned the number len(dictionary).
# Example: for a 26-char alphabet, the first letter is 0 and 26 represents an unknown char.
def makenumbers(text_input, dictionary):
	digits = []
	for letter in text_input:
		if letter in dictionary:
			digits.append(dictionary[letter])
		else:
			digits.append(len(dictionary))
			# if <dictionary> is e.g. 42 chars long, 42 will represent an unencodable character.
	return digits

# This function translates a number list into a string of text using an alphabet.
# Any number not represented by a char in the alphabet is represented as a space.
def makeletters(number_list, alphabet):
	letters = ""
	for i in range ( len(number_list) ) :
		if number_list[i] >= len(alphabet) :
			letters += " "
		else :
			letters += alphabet[ number_list[i] ]
	return letters

# This function "packs" a list of 2-digit ints into a list of long ints with 2 *<halfsize> or fewer digits.
# For RSA to work, we must package the plaintext as a list of numbers less than the RSA number <rsan>.
# The key generator in this program never produces an RSA number less than 2363807161,
# so any decimal number with 9 or fewer digits is OK.  The main program uses 8-digit packets.
# Requires Python random library.
def makepackets(numberlist, halfsize) :
	packetlist = []
	packetsize = halfsize * 2		# expecting an input list of 2-digit numbers
	padsize = packetsize - ( (2 * len(numberlist)) % packetsize	) # number of extra digits to pad onto last packet
	if len(numberlist) < halfsize :
		padsize = packetsize - 2 * len(numberlist)	# exceptional case for very short messages
	count = 0
	while count < ( len(numberlist) - halfsize ) :
		packet = ""
		for j in range(0, halfsize) :
			packet += str(numberlist[ count + j ]).zfill(2)		# zfill restores any leading zeros
		packetlist.append(long(packet))
		count = count + halfsize
	# now the last packet is padded with random digits until it is the appropriate size
	packet = ""
	for k in range(count , len(numberlist), 1) :	# fill last packet
		packet += str(numberlist[k]).zfill(2)
		if len(packet) == packetsize :			# if packet is exactly full, create an extra one anyway
			packetlist.append(long(packet))
			packet = ""
	for l in range(0, padsize -1 , 1) :			# pad with random digits
		packet += str(random.randint(0,9))
	packet += str(padsize)		# last digit is "number of digits to discard later"
	packetlist.append(long(packet))
	return packetlist

# This function "unpacks" a list of 2*<halfsize>-digit longs to produce a list of ints between 0-99 inclusive.
def unpack(packetlist, halfsize) :
	packetsize = halfsize * 2
	outputlist = []
	packet = ""
	for i in range(0, len(packetlist) - 1, 1) :		# last packet will be handled after this loop
		packet = str(packetlist[i]).zfill(packetsize)	# zfill restores any leading zeros
		for j in range(0, packetsize, 2) :
			outputlist.append(int(packet[j:j+2]))
	packet = str(packetlist[ len(packetlist) - 1 ]).zfill(packetsize)
	padsize = int(packet[ packetsize - 1 ])			# remember, last digit of last packet is padsize.
	packet = packet[:-padsize]						# deletes extra padding from last packet
	for k in range(0, len(packet), 2) :
		outputlist.append(int(packet[k:k+2]))
	return outputlist

# This function outputs an encrypted string of text using a Caesar cipher.
# Inputs: text message, chosen alphabet, dictionary, and number of chars to shift.
# ROT13 is a shift of 13; the classic Caesar cipher is a shift of 3.
def caesarshift(message, alphabet, dictionary, shift):
	numberlist = makenumbers(message, dictionary)
	for i in range( len(numberlist) ) :
		if numberlist[i] < len(alphabet) :
			numberlist[i] = (numberlist[i] + shift) % (len(alphabet))
			# Characters not in the selected alphabet are left unencrypted.
	return makeletters(numberlist, alphabet)
	
# This function encrypts a string of text using a polyalphabetic cipher.
# Note that this scheme requires a password input; this password works as a shared key.
def dodgsonencrypt(message, alphabet, dictionary, password):
	numberlist = makenumbers(message, dictionary)
	keystring = ""
	# Produce a key.  If password is FIDELIO and message is 15-21 chars long, key is FIDELIOFIDELIOFIDELIO
	for j in range( len(numberlist) / len(password) + 1 ) :
		keystring += password
	# Convert key into a list of numbers, then apply polyalphabetic cipher to original message.
	keylist = makenumbers(keystring, dictionary)
	for i in range ( len(numberlist) ) :
		if numberlist[i] < len(alphabet) :
			numberlist[i] = (numberlist[i] + keylist[i] + 1 ) % (len(alphabet))
	return makeletters(numberlist, alphabet)
	
# This function decrypts the polyalphabetic cipher from the previous function.
def dodgsondecrypt(ciphertext, alphabet, dictionary, password):
	numberlist = makenumbers(ciphertext, dictionary)
	keystring = ""
	for j in range( len(numberlist) / len(password) + 1 ) :
		keystring += password
	keylist = makenumbers(keystring, dictionary)
	for i in range ( len(numberlist) ) :
		if numberlist[i] < len(alphabet) :
			numberlist[i] = (numberlist[i] - keylist[i] - 1) % (len(alphabet))
	return makeletters(numberlist, alphabet)
	
# This function performs frequency analysis on an input string.
def freqanalyze(inputstring):
	freqdict = {}				# list of chars and the number of times that char appears
	for c in inputstring :
		if c in freqdict :
			freqdict[c] = freqdict[c] +1
		else :
			freqdict[c] = 1
	resultlist = sorted(freqdict.items(), key=lambda (k,v): v, reverse=True)	# sort letters by value
	return resultlist

# This function uses the extended Euclidean algorithm to find the multiplicative inverse of x (mod phi).
# It is needed to generate keys for RSA encryption.
def findinverse(x, phi):		
	nlist = [phi, x]
	plist = [long(0)]
	alist = [long(1),long(0)]
	blist = [long(0),long(1)]

	if nlist[0] % nlist[1] == 0 :
		print "Error! Public key is not coprime to totient."
	else :
		count = int(0)
		r = long(1)
		while r != 0 :
			plist.append( nlist[count] / nlist[count + 1] )						# creates p(count+1)
			alist.append( alist[count] - plist[count + 1] * alist[count + 1] ) 	# creates a(count+2)
			blist.append( blist[count] - plist[count + 1] * blist[count + 1] )	# creates b(count+2)
			r = nlist[count] % nlist[count + 1]
			nlist.append(r)														# creates phi(count+2)
			count = count + 1
	return blist[count] % phi

# This function generates an RSA number, totient, public and private key stored as a list.
# Requires the function <findinverse>, Python random library, and file "10000primes.txt" to work.
def generatekey():
	primesfile = open("10000primes.txt", "r")
	primeslist = primesfile.read().split()
	prime0 = int(primeslist[random.randint(5000,len(primeslist))])	# The first 5000 primes are not used.
	prime1 = int(prime0)		# initialize <prime1>
	while prime1 == prime0 :		# This loop ensures that the two primes are not the same.
		prime1 = int(primeslist[random.randint(5000,len(primeslist))])
	totient = (prime0 - 1) * (prime1 - 1)
	rsan = prime0 * prime1
	# Choose a (prime) public key that is large but less than the totient.
	publickey = 10968163441			# This is the 10000th prime squared; totient is less than this
	while publickey > totient:
		publickey = int(primeslist[random.randint(5000,len(primeslist))])	# First 5000 primes not used.	
	# <findinverse> finds the multiplicative inverse of the public key (mod totient).
	privatekey = findinverse(publickey, totient)
	RSAkeylist = [prime0, prime1, rsan, publickey, privatekey, totient]
	return RSAkeylist

# These functions encypt and decrypt a list of long ints using the RSA scheme.
# Requires function <modexp> for fast modular exponentiation.
def RSAencrypt(packetlist, rsan, publickey):
	cipherlist = []
	cipherpacket = ""
	for i in range(len(packetlist)) :
		cipherlist.append( modexp( packetlist[i], publickey, rsan ) )
	return cipherlist

def RSAdecrypt(cipherlist, rsan, privatekey):
	decryptedlist = []
	for i in range(len(cipherlist)) :
		decryptedlist.append( modexp( cipherlist[i] , privatekey , rsan ) )
	return decryptedlist

# This function performs fast modular exponentiation of large numbers.
# Author: Wojtek Jamrozy (www.wojtekrj.net)
def modexp(a, n, m):
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

# This function asks the user to select an alphabet from the ones defined in Global Variables.
# If you add your own alphabets, be sure to modify this function to include it.
def selectalphabet():
	size = raw_input("Select alphabet size: [26] [42] [96] or hit Enter for default of 96. \t\t")
	if size == "26" :
		alphabet = ALPHABET26
		dictionary = LOOKUP26
	elif size == "42" :
		alphabet = ALPHABET42
		dictionary = LOOKUP42
	else :
		alphabet = ALPHABET96
		dictionary = LOOKUP96
		print "Using 96-character alphabet."
	return (alphabet, dictionary)



# ----------------- GLOBAL VARIABLES -------------------------------

# A map from characters to integers and back is represented here by two parts:
# 1) an ALPHABET tuple that lists the chars in order (used for converting numbers -> text), and
# 2) a LOOKUP dictionary (made from the corresponding ALPHABET) for converting text -> numbers.
# If you want to add your own alphabet, be sure to modify the function <selectalphabet> accordingly!
# WARNING: this program can only handle alphabets with 99 or fewer characters!

# traditional 26-letter alphabet for classical encryption schemes
ALPHABET26 = ('A','B','C','D','E','F','G','H','I',\
			'J','K','L','M','N','O','P','Q','R','S',\
			'T','U','V','W','X','Y','Z')
LOOKUP26 = {}
for i in range (0,26,1):
	LOOKUP26[ ALPHABET26[i] ] = i

# 42-char alphabet for basic text messaging
ALPHABET42 = ('0','1','2','3','4','5','6','7','8','9',\
			' ','A','B','C','D','E','F','G','H','I',\
			'J','K','L','M','N','O','P','Q','R','S',\
			'T','U','V','W','X','Y','Z',',','.','\'',\
			'?','!')
LOOKUP42 = {}
for i in range (0,42,1):
	LOOKUP42[ ALPHABET42[i] ] = i

# 96-char alphabet of ASCII chars 32-127 (0-31 are system commands not typically used in text messages).
# note that the list of characters is actually a list, not a tuple
ALPHABET96 = []
for i in range(32,128):
	ALPHABET96.append( chr(i) )
LOOKUP96 = {}
for j in range(96):
	LOOKUP96[ ALPHABET96[j] ] = j
