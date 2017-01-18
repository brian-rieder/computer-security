__author__ = 'brieder'

from string import ascii_letters
from collections import deque
from itertools import cycle


def create_vigenere_table():
    vig_table = {}
    sub_letters = deque(ascii_letters)
    for upper_letter in ascii_letters:
        vig_table[upper_letter] = {}
        for lower_letter, sub_letter in zip(ascii_letters, sub_letters):
            vig_table[upper_letter][lower_letter] = sub_letter
        sub_letters.rotate()
    return vig_table


def vigenere_cipher_encrypt(input_text, key):
    ciphertext = ""
    vig_table = create_vigenere_table()
    for input_char, key_char in zip(input_text, cycle(key)):
        ciphertext += vig_table[input_char][key_char]
    return ciphertext


def vigenere_cipher_decrypt(encrypted_text, key):
    decrypted_text = ""
    vig_table = create_vigenere_table()
    for encrypted_char, key_char in zip(encrypted_text, cycle(key)):
        for input_key in vig_table.keys():
            if vig_table[input_key][key_char] == encrypted_char:
                decrypted_text += input_key
                break
    return decrypted_text


if __name__ == '__main__':
    with open('input.txt') as input_file:
        input_string = input_file.read()
    with open('key.txt') as key_file:
        key_string = key_file.read()
    cipher_string = vigenere_cipher_encrypt(input_string, key_string)
    decrypt_string = vigenere_cipher_decrypt(cipher_string, key_string)
    print("Original:  " + input_string)
    print("Encrypted: " + cipher_string)
    print("Decrypted: " + decrypt_string)
