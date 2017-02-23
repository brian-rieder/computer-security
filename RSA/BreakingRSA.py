#!/usr/bin/env python2.7

# Breaking RSA
# Brian Rieder
__author__ = 'brieder'

from BitVector import *
from PrimeGenerator import *
from solve_pRoot import *
import os
import sys

e = 3


def bgcd(a, b):
    if a == b: return a
    if a == 0: return b
    if b == 0: return a
    if ~a & 1:
        if b & 1: return bgcd(a >> 1, b)
        else: return bgcd(a >> 1, b >> 1) << 1
    if ~b & 1: return bgcd(a, b >> 1)
    if a > b: return bgcd((a-b) >> 1, b)
    return bgcd((b-a) >> 1, a)


def generate_key_pair():
    prime_gen = PrimeGenerator(bits=128, debug=0)
    while True:
        p = prime_gen.findPrime()
        q = prime_gen.findPrime()
        if p == q: continue  # ensure that the extremely unlikely case of p=q didn't occur
        if not (bin(p)[2] and bin(p)[3] and bin(q)[2] and bin(q)[3]): continue  # ensure leading bits are 1
        if (bgcd(p-1, e) != 1) or (bgcd(q-1, e) != 1): continue  # totients must be co-prime to e
        break
    mod_n = p * q  # modulus is the product of the primes
    tot_n = (p-1) * (q-1)  # totient of n
    mod_bv = BitVector(intVal=tot_n)
    e_bv = BitVector(intVal=e)
    d_loc = int(e_bv.multiplicative_inverse(mod_bv))
    return (e, mod_n), (d_loc, mod_n), p, q


def write_private_key(private_key, p, q, key_num):
    with open('private_key' + str(key_num) + '.txt', 'w') as private_file:
        private_file.write("d: " + str(private_key[0]) + "\n")
        private_file.write("n: " + str(private_key[1]) + "\n")
        private_file.write("p: " + str(p) + "\n")
        private_file.write("q: " + str(q) + "\n")


def open_file_for_rsa(filename, is_encrypted):
    file_size = os.path.getsize(filename)
    file_bv = BitVector(filename=filename)
    if is_encrypted:  # no need to pad, just start reading
        blocked_contents = []
        for _ in range(0, file_size/32):
            blocked_contents.append(int(file_bv.read_bits_from_file(256)))
        return blocked_contents  # we can just jump out here, there's no padding necessary on decryption
    else:  # we're plaintext, let's partition the data
        blocked_contents = []
        for _ in range(0, file_size / 16 + 1):  # split the file into 16 byte chunks
            blocked_contents.append(file_bv.read_bits_from_file(128))  # read 16 bytes
    bv_nl = BitVector(textstring='\n')
    while len(blocked_contents[-1]) < 128:  # last block has to be 128 bits
        blocked_contents[-1] += bv_nl  # append newlines up to 128 as needed
    for block in blocked_contents:
        block.pad_from_left(128)
    blocked_contents = map(int, blocked_contents)
    return blocked_contents


def encrypt(filename, public_key):
    encrypted = []
    file_to_encrypt = open_file_for_rsa(filename, is_encrypted=False)
    for block in file_to_encrypt:
        encrypted.append(pow(block, public_key[0], public_key[1]))
    return encrypted


def write_encrypted(filename, encrypted_list):
    with open(filename, 'w') as output_file:
        for data_block in encrypted_list:
            block_bv = BitVector(intVal=data_block, size=256)
            output_file.write(block_bv.get_text_from_bitvector())
    with open(filename + '.hex', 'w') as output_file:
        for data_block in encrypted_list:
            block_bv = BitVector(intVal=data_block, size=256)
            output_file.write(block_bv.get_bitvector_in_hex())


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: " + sys.argv[0] + " message.txt cracked.txt")
    elif os.path.isfile(sys.argv[1]) and os.access(sys.argv[1], os.R_OK):
        # generate three sets of public and private keys with e = 3 (defined globally)
        public_key1, private_key1, p1, q1 = generate_key_pair()
        public_key2, private_key2, p2, q2 = generate_key_pair()
        public_key3, private_key3, p3, q3 = generate_key_pair()

        # write the keys to their files
        write_private_key(private_key1, p1, q1, 1)
        write_private_key(private_key2, p2, q2, 2)
        write_private_key(private_key3, p3, q3, 3)

        # encrypt the given plaintext with each of the three public keys
        encrypted1 = encrypt(sys.argv[1], public_key1)
        write_encrypted('encrypted1.txt', encrypted1)
        encrypted2 = encrypt(sys.argv[1], public_key2)
        write_encrypted('encrypted2.txt', encrypted2)
        encrypted3 = encrypt(sys.argv[1], public_key3)
        write_encrypted('encrypted3.txt', encrypted3)
        encrypted_length = len(encrypted1)

        # generate N values
        N = public_key1[1] * public_key2[1] * public_key3[1]
        N1 = N / public_key1[1]
        N2 = N / public_key2[1]
        N3 = N / public_key3[1]

        # calculate multiplicative inverses
        C1 = int(BitVector(intVal=N1).multiplicative_inverse(BitVector(intVal=public_key1[1])))
        C2 = int(BitVector(intVal=N2).multiplicative_inverse(BitVector(intVal=public_key2[1])))
        C3 = int(BitVector(intVal=N3).multiplicative_inverse(BitVector(intVal=public_key3[1])))

        # perform the actual crack using CRT
        crack_bv = BitVector(size=0)
        for i in range(0, encrypted_length):
            x1 = encrypted1[i] * N1 * C1
            x2 = encrypted2[i] * N2 * C2
            x3 = encrypted3[i] * N3 * C3
            x = (x1 + x2 + x3) % N
            # M = pow(x, 1/3) does not have the precision
            M = solve_pRoot(3, x)
            crack_bv += BitVector(intVal=M, size=128)
        with open(sys.argv[2], 'w') as cracked_file:
            cracked_file.write(crack_bv.get_text_from_bitvector())
    else:
        print("File " + sys.argv[2] + " does not exist or cannot be read.")
