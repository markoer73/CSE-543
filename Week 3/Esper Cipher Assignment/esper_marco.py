import argparse
import os
import time
import sys
import string

# Handle command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-d", "--decrypt", help='Decrypt a file', required=False)
parser.add_argument("-e", "--encrypt", help='Encrypt a file', required=False)
parser.add_argument("-o", "--outfile", help='Output file', required=False)
parser.add_argument("-k", "--key",     help='Key - only used for decryption', required=False)
parser.add_argument("-b", "--bits",    help='Bits for key rotation - only used for decryption', required=False)

args = parser.parse_args()

ENCRYPTING = True

try:
    ciphertext = open(args.decrypt, "rb").read()
    try:
        plaintext = open(args.encrypt, "rb").read()
        print("You can't specify both -e and -d")
        exit(1)
    except Exception:
        ENCRYPTING = False
    try:
        decryptkey = args.key
        if len (decryptkey) != 7:
            print("I am sorry, the key needs to be an ASCII string of 7 characters")
            exit(1)           
    except Exception:
        print("In case of decryption, you need to specify a key with -k")
        exit(1)
    try:
        rotatebits = int(args.bits)
        if rotatebits > 8 or rotatebits < 1:
            print("Sorry, the number of bits for key rotation needs to be a number between 1 and 8")
            exit(1)
    except Exception:
        print("In case of decryption, you need to specify the number of bits for key rotation with -b as a number between 1 and 8")
        exit(1)
except Exception:
    try:
        plaintext = open(args.encrypt, "rb").read()
    except Exception:
        print("Input file error (did you specify -e or -d?)")
        exit(1)

def lrot(n, d):
    return ((n << d) & 0xff) | (n >> (8 - d))

def rrot(n, d):
    return ((n >> d)) | ((n << (8 - d)) & 0xff)

if ENCRYPTING:
    #
    # Esper cipher
    #

    # Get the key
    keybytes = bytes(os.urandom(8))
    keyrotate = keybytes[0] % 7 + 1
    keyxor = []
    key = ""
    # Rotate the key
    for i in range(1, 8):
        keyxor.append(ord(string.ascii_letters[keybytes[i] % len(string.ascii_letters)]))
        key = key + chr(keyxor[i-1])

    # For debug purposes, set a fixed key and bits
    key = "yyseLsC"
    keyxor = [121, 121, 115, 101, 76, 115, 67]
    keyrotate = 1
    print("The key is %s rotated by %d bits." % (key, keyrotate))

    ciphertext = []
    for i in range(0, len(plaintext)):
        ciphertext.append(lrot(plaintext[i], keyrotate) ^ keyxor[i % len(keyxor)])

#       Debug
#        rotl = lrot(plaintext[i], keyrotate)
#        kx = keyxor[i % len(keyxor)]
#        kx1 = ord(key[i % len(key)])
#        ct = rotl ^ kx
#        ct1 = rotl ^ kx1
#        ciphertext.append(ct)
#        tc = ct ^ kx
#        pt = rrot(tc, keyrotate)

    with open(args.outfile, "wb") as output:
        output.write(bytes(ciphertext))
        output.close()
else:
    #
    # Esper cipher decyption
    #
    plaintext = ""
    for i in range(0, len(ciphertext)):
        plaintext += chr(rrot(ciphertext[i] ^ ord(decryptkey[i % len(decryptkey)]), rotatebits))

#       Debug
#        kx1 = ord(decryptkey[i % len(decryptkey)])
#        ct1 = ciphertext[i] ^ kx1
#        rotr = rrot(ct1, rotatebits)
#        plaintext += chr (rotr)
        
    print("The plaintext is: ", plaintext)
