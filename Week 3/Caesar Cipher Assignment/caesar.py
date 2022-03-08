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

args = parser.parse_args()

encrypting = True

try:
    ciphertext = open(args.decrypt, "rb").read()
    try:
        plaintext = open(args.encrypt, "rb").read()
        print("You can't specify both -e and -d")
        exit(1)
    except Exception:
        encrypting = False
except Exception:
    try:
        plaintext = open(args.encrypt, "rb").read()
    except Exception:
        print("Input file error (did you specify -e or -d?)")
        exit(1)


if encrypting:
    keybytes = bytes(os.urandom(1))
    keyrotate = int(keybytes[0] % 25) + 1
    print("Key is " + string.ascii_uppercase[keyrotate])
    ciphertext = ""

    for i in range(0, len(plaintext)):
        if chr(plaintext[i]) in string.ascii_uppercase:
            p = plaintext[i] - ord('A')
            c = chr(ord('A') + ((p + keyrotate) % 26))
            ciphertext = ciphertext + c
        else:
            print("Incorrect input character %s." % plaintext[i])

    with open(args.outfile, "wb") as output:
        output.write(ciphertext.encode("ascii"))
        output.close()
else:
    print("Decryption is not implemented!")
    exit(1)
