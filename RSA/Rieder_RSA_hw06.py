#!/usr/bin/env python2.7

# RSA Encryption and Decryption
# Brian Rieder
__author__ = 'brieder'

from BitVector import *
from PrimeGenerator import *
import sys
import os

e = 65537


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


def chinese_remainder_theorem(encrypted_file, private_d, private_p, private_q):
    crt_p, crt_q = [], []
    for block in encrypted_file:
        crt_p.append(pow(block, private_d, private_p))
        crt_q.append(pow(block, private_d, private_q))
    return crt_p, crt_q


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


def read_private_key(key_file):
    key_lines = key_file.readlines()
    p_d, p_n, p_p, p_q = key_lines
    p_d = p_d.split(':')
    p_n = p_n.split(':')
    p_p = p_p.split(':')
    p_q = p_q.split(':')
    if p_d[0] == 'd' and p_n[0] == 'n' and p_p[0] == 'p' and p_q[0] == 'q':
        return int(p_d[1].strip()), int(p_n[1].strip()), int(p_p[1].strip()), int(p_q[1].strip())
    else:
        print("Illegal private key file format.")
        sys.exit()


def encrypt(filename, public_key):
    encrypted = []
    file_to_encrypt = open_file_for_rsa(filename, is_encrypted=False)
    for block in file_to_encrypt:
        encrypted.append(pow(block, public_key[0], public_key[1]))
    return encrypted


def decrypt(filename, private_key, dec_p, dec_q):
    decrypted = []
    private_d, private_n = private_key
    encrypted_file = open_file_for_rsa(filename, is_encrypted=True)
    p_crt, q_crt = chinese_remainder_theorem(encrypted_file, private_d, dec_p, dec_q)
    p_bv = BitVector(intVal=p)
    q_bv = BitVector(intVal=q)
    for i in range(0, len(encrypted_file)):
        decrypted.append((p_crt[i] * q * int(q_bv.multiplicative_inverse(p_bv))
                          + q_crt[i] * p * int(p_bv.multiplicative_inverse(q_bv))) % private_n)
    return decrypted


if __name__ == '__main__':
    if len(sys.argv) != 4 or (sys.argv[1] != '-e' and sys.argv[1] != '-d'):
        print("Usage:")
        print("Encryption: " + sys.argv[0] + " -e message.txt output.txt")
        print("Decryption: " + sys.argv[0] + " -d output.txt decrypted.txt")
    elif os.path.isfile(sys.argv[2]) and os.access(sys.argv[2], os.R_OK):
        if sys.argv[1] == '-e':
            public, private, p, q = generate_key_pair()
            # record the public key
            with open('public_key.txt', 'w') as public_file:
                public_file.write("e: " + str(public[0]) + "\n")
                public_file.write("n: " + str(public[1]) + "\n")
            # record the private key
            with open('private_key.txt', 'w') as private_file:
                private_file.write("d: " + str(private[0]) + "\n")
                private_file.write("n: " + str(private[1]) + "\n")
                private_file.write("p: " + str(p) + "\n")
                private_file.write("q: " + str(q) + "\n")
            encrypted_list = encrypt(sys.argv[2], public)
            with open(sys.argv[3], 'w') as output_file:
                for data_block in encrypted_list:
                    block_bv = BitVector(intVal=data_block, size=256)
                    output_file.write(block_bv.get_text_from_bitvector())
        elif sys.argv[1] == '-d':
            if not os.path.isfile('private_key.txt') or not os.access('private_key.txt', os.R_OK):
                print("Private key file 'private_key.txt' doesn't exist or cannot be read.")
                sys.exit()
            with open('private_key.txt', 'r') as private_file:
                d, n, p, q = read_private_key(private_file)
            decrypted_list = decrypt(sys.argv[2], (d, n), p, q)
            with open(sys.argv[3], 'w') as output_file:
                for data_block in decrypted_list:
                    block_bv = BitVector(intVal=data_block, size=128)
                    output_file.write(block_bv.get_text_from_bitvector())
    else:
        print("File " + sys.argv[2] + " does not exist or cannot be read.")
