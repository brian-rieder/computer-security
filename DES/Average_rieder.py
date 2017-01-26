#!/usr/bin/env python2.7

# Diffusion and Confusion Analysis
# Brian Rieder
__author__ = 'brieder'


from BitVector import *
import os
from random import randint
from DES_rieder import *


def change_one_bit(filename):
    """
    Changes one bit in a file.
    :param filename: The file to alter
    """
    temp_file = open('bitdiff.txt','w')
    bitvec = BitVector(filename=filename)
    file_length = os.path.getsize(filename) * 8  # get file length in bits
    bits = bitvec.read_bits_from_file(file_length)  # read entire file
    bit_to_change = randint(0, file_length-1)  # choose a random bit location in the full bounds of the file
    bits[bit_to_change] = 0 if bits[bit_to_change] == 1 else 1  # flip the bit
    bits.write_to_file(temp_file)
    temp_file.close()
    bitvec.close_file_object()


def find_number_of_bit_diff(filename1, filename2):
    """
    Calculates the number of different bits between two files.
    :param filename1: First file for comparison
    :param filename2: Second file for comparison
    :return: The total number of bits different between the files
    """
    total_bits_different = 0
    # read entirety of first file in a bitstring
    bv1 = BitVector(filename=filename1)
    file_length = os.path.getsize('avg1.txt') * 8
    bits1 = bv1.read_bits_from_file(file_length)
    # read entirety of second file in a bitstring
    bv2 = BitVector(filename=filename2)
    file_length = os.path.getsize('avg2.txt') * 8
    bits2 = bv2.read_bits_from_file(file_length)

    bit_difference = bits1 ^ bits2  # XOR leaves 1's where different
    # count the 1's in the bit comparison
    for bit in bit_difference:
        if int(bit) == 1:
            total_bits_different += 1
    return total_bits_different


def diffusion_averaging(num_iter):
    """
    Determines the average number of bits changed by changing a single bit in the input.
    :param num_iter: The number of iterations to analyze
    """
    with open('key.txt') as key_file:
        key_text = key_file.read()
    if len(key_text) != 8:
        raise ValueError("Key length must be 8.")
    total_bits_different = 0
    for _ in range(0, num_iter):
        des_encryption(key_text, 'message.txt', 'avg1.txt', encrypt=True)        # encrypt the message
        change_one_bit('message.txt')                                            # flip a bit
        des_encryption(key_text, 'bitdiff.txt', 'avg2.txt', encrypt=True)        # encrypt the flipped message
        total_bits_different += find_number_of_bit_diff('avg1.txt', 'avg2.txt')  # determine the difference
    total_bits_different /= num_iter  # divide to compute average
    print("Diffusion - Average number of bits different with one input bit changed in "
          + str(num_iter) + " iterations: " + str(total_bits_different))


def confusion_averaging(num_iter):
    """
    Determines the average number of bits changed by changing a single bit in the key.
    :param num_iter: The number of iterations to analyze
    """
    with open('key.txt') as key_file:
        key_text = key_file.read()
    if len(key_text) != 8:
        raise ValueError("Key length must be 8.")
    total_bits_different = 0
    for _ in range(0, num_iter):
        with open("key.txt") as key_file:
            key_text = key_file.read()
        des_encryption(key_text, 'message.txt', 'avg1.txt', encrypt=True)        # encrypt the message
        change_one_bit('key.txt')                                                # flip a bit in the key
        with open("bitdiff.txt") as key_file:
            key_text = key_file.read()
        des_encryption(key_text, 'message.txt', 'avg2.txt', encrypt=True)        # encrypt the message with flipped key
        total_bits_different += find_number_of_bit_diff('avg1.txt', 'avg2.txt')  # determine the difference
    total_bits_different /= num_iter  # divide to compute average
    print("Confusion - Average number of bits different one key bit changed in "
          + str(num_iter) + " iterations: " + str(total_bits_different))


def substitute_random_s_box(expanded_half_block):
    """
    Performs normal DES S-box substitution, but generates randomized S-boxes before performing substitution.
    :param expanded_half_block: The 48-bit output of the expansion permutation XORed with the round key
    :return: 32-bit S-box substituted result
    """
    # generate random S-boxes
    random_s_boxes = {i: [[], [], [], []] for i in range(8)}
    for i in range(0, 8):
        for j in range(0, 4):
            for k in range(0, 16):
                random_s_boxes[i][j].append(randint(0, 15))

    # perform normal substitution
    output = BitVector(size=32)
    segments = [expanded_half_block[x * 6:x * 6 + 6] for x in range(8)]
    for sindex in range(len(segments)):
        row = 2 * segments[sindex][0] + segments[sindex][-1]
        column = int(segments[sindex][1:-1])
        output[sindex * 4:sindex * 4 + 4] = BitVector(intVal=random_s_boxes[sindex][row][column], size=4)
    return output


def des_encryption_random_s_boxes(key_string, input_filename, output_filename, encrypt):
    """
    Same as normal DES, but utilizes randomized S-boxes.
    :param key_string: 8-character input string used as a key
    :param input_filename: File to be read from
    :param output_filename: File to be written to
    :param encrypt: Boolean that determines DES operation: True=Encrypt, False=Decrypt
    :return: None - outputs to file
    """
    key = get_encryption_key(key_string)   # generate the 56-bit encryption key
    round_keys = generate_round_keys(key)  # generate the round keys from the encryption key
    bv = BitVector(filename=input_filename)
    output_file = open(output_filename, 'w')
    while bv.more_to_read:
        bitvec = bv.read_bits_from_file(64)  # process 8 bytes at a time
        [LE, RE] = bitvec.divide_into_two()
        if bitvec.length() > 0:
            for round_key in round_keys if encrypt else round_keys[::-1]:  # True->in-order, False->reverse-order
                newLE = RE.deep_copy()  # maintain a copy to avoid right half bastardization
                RE = RE.permute(expansion_permutation)          # permute 32 bit half to 48 bits
                out_xor = RE ^ round_key                        # XOR with round key
                s_output = substitute_random_s_box(out_xor)     # substitution with RANDOMIZED S-boxes
                p_output = s_output.permute(p_box_permutation)  # permute with P-box
                RE = LE ^ p_output                              # the new right is the old left XORed with p-permutation
                LE = newLE                                      # the new left is simply the old right
        bitvec = RE + LE                                        # the result is the concatenation of the two
        bitvec.write_to_file(output_file)
    output_file.close()


def s_box_diffusion():
    """
    Analyzes the effect of diffusion caused by randomizing the S-boxes and checking the number of bits varying in the
    ciphertext. Per the specification, two iterations of randomized S-boxes are performed and printed.
    """
    with open('key.txt') as key_file:
        key_text = key_file.read()
    if len(key_text) != 8:
        raise ValueError("Key length must be 8.")
    des_encryption(key_text, 'message.txt', 'avg1.txt', encrypt=True)  # perform the original encryption
    for _ in range(0, 2):
        des_encryption_random_s_boxes(key_text, 'message.txt', 'avg2.txt', encrypt=True)  # encrypt with random S-boxes
        total_bits_different = find_number_of_bit_diff('avg1.txt', 'avg2.txt')            # determine bit difference
        print("Diffusion - Number of bits different with randomized S-boxes: " + str(total_bits_different))


if __name__ == '__main__':
    # In order to change inputs:
    # 1) Change the key to encode with in key.txt
    # 2) Change the message to encode in message.txt
    # NOTE: Runtime is heavily based on the number of iterations. Keep the number relatively low.
    # Effects of Diffusion: Change one bit in the input
    diffusion_averaging(num_iter=5)
    # Effects of S-boxes on diffusion: Randomize S-boxes
    s_box_diffusion()
    # Effects of Confusion: Change one bit in the key
    confusion_averaging(num_iter=5)
