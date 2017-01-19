__author__ = 'brieder'

from string import ascii_letters
from collections import deque
from itertools import cycle


def create_vigenere_table():
    """
    Generates a Vigenere table using an ASCII alphabet A-Za-z
    :return: Complete Vigenere table
    """
    vig_table = {}
    sub_letters = deque(ascii_letters)  # cyclic queue for substitution
    for upper_letter in ascii_letters:
        vig_table[upper_letter] = {}
        for lower_letter, sub_letter in zip(ascii_letters, sub_letters):
            vig_table[upper_letter][lower_letter] = sub_letter
        sub_letters.rotate()  # cycle the queue
    return vig_table


def vigenere_cipher_encrypt(input_text, key):
    """
    Encrypts and returns an input string using a Vigenere table
    :param input_text: The string to be encrypted
    :param key: The key to encrypt with. This is cyclic: blah becomes blahblahbl...
    :return: Encrypted text
    """
    ciphertext = ""
    vig_table = create_vigenere_table()
    for input_char, key_char in zip(input_text, cycle(key)):  # generate pairs with input and cycled key
        ciphertext += vig_table[input_char][key_char]
    return ciphertext


def vigenere_cipher_decrypt(encrypted_text, key):
    """
    Decrypts an encrypted string and returns the decrypted value
    :param encrypted_text: The string to be decrypted
    :param key: The key to decrypt with. This is cyclic: blah becomes blahblahbl...
    :return: Decrypted text
    """
    decrypted_text = ""
    vig_table = create_vigenere_table()
    for encrypted_char, key_char in zip(encrypted_text, cycle(key)):  # generate pairs with input and cycled key
        for input_key in vig_table.keys():  # not as efficient as hashing, searches linearly through keys
            if vig_table[input_key][key_char] == encrypted_char:
                decrypted_text += input_key
                break  # exit inner loop when the decrypted value was found
    return decrypted_text


if __name__ == '__main__':
    # Inputs are read from 'input.txt' and 'key.txt' per design specification
    with open('input.txt') as input_file:
        input_string = input_file.read()
    with open('key.txt') as key_file:
        key_string = key_file.read()

    # Display original, encrypted, and decrypted strings for demonstration
    cipher_string = vigenere_cipher_encrypt(input_string, key_string)
    decrypt_string = vigenere_cipher_decrypt(cipher_string, key_string)
    print("Original:  " + input_string)
    print("Encrypted: " + cipher_string)
    print("Decrypted: " + decrypt_string)

    # Write output to file
    with open('output.txt','w') as output_file:
        output_file.write(cipher_string)
