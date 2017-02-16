#!/usr/bin/env python2.7

# RC4 Encryption and Decryption
# Brian Rieder
__author__ = 'brieder'


class RC4:
    state_vector = list(range(256))

    def __init__(self, key_string):
        """
        Permutes the state vector using the input key.
        - key_string: Key string input by the user
        - key_list: ASCII-numerical integer list representation of key
        - encrypted_list: Byte-list of last executed encryption
        - decrypted_list: Byte-list of last executed decryption
        """
        self.key_string = key_string
        self.key_list = [ord(i) for i in key_string]
        self.encrypted_list = []
        self.decrypted_list = []
        j = 0
        key_length = len(key_string)
        for i in range(256):
            j = (j + self.state_vector[i] + self.key_list[i % key_length]) % 256
            self.state_vector[i], self.state_vector[j] = self.state_vector[j], self.state_vector[i]

    def execute_cipher(self, image_contents):
        """
        The meat of RC4. Goes byte-by-byte through the given contents and performs XOR combination based
        on the state vector generated upon object creation
        :param image_contents: Content read from the input file (string or list format)
        :return: Encrypted or decrypted array of file contents
        """
        new_img = [ord(c) if type(image_contents[0]) is str else c for c in image_contents]
        local_states = self.state_vector[:]
        i, j, byte_count = 0, 0, 0
        processed = []
        while True:
            i = (i + 1) % 256
            j = (j + local_states[i]) % 256
            local_states[i], local_states[j] = local_states[j], local_states[i]
            xor_byte = (local_states[i] + local_states[j]) % 256
            processed.append(local_states[xor_byte] ^ new_img[byte_count])
            byte_count += 1
            if byte_count == len(new_img):
                break
        return processed

    def encrypt(self, image_file):
        """
        Takes an input file object, encrypts it, writes the output to a file, and returns the encrypted file object
        :param image_file: File object to be encrypted
        :return: Encrypted file object
        """
        image_contents = image_file.read()
        encrypted_image = self.execute_cipher(image_contents)
        output_file = open("encryptedImage.ppm", 'w+b')
        output_file.write(bytearray(encrypted_image))
        self.encrypted_list = encrypted_image  # maintains a copy of the encrypted output (debug purposes)
        output_file.seek(0, 0)  # set the file marker back to the beginning for reading purposes
        return output_file

    def decrypt(self, image_file):
        """
        Takes an input file object, decrypts it, writes the output to a file, and returns the encrypted file object
        :param image_file: File object to be decrypted
        :return: Decrypted file object
        """
        image_contents = image_file.read()
        decrypted_image = self.execute_cipher(image_contents)
        output_file = open("decryptedImage.ppm", 'wba')
        output_file.write(bytearray(decrypted_image))
        self.decrypted_list = decrypted_image  # maintains a copy of the decrypted output (debug purposes)
        output_file.seek(0, 0)  # set the file marker back to the beginning for reading purposes
        return output_file

if __name__ == '__main__':
    rc4cipher = RC4('keystring')
    original_image = "winterTown.ppm"
    with open(original_image, 'r') as img_file:
        img_contents = img_file.readlines()
        img_header = img_contents[:3]
        img_data = img_contents[3:]
    headerless_img = open("winterTownNoHeader.ppm", 'r')
    encrypted_file = rc4cipher.encrypt(headerless_img)
    with open("viewable_encrypted.ppm", 'wba') as test_file:
        for header_line in img_header[0:3]:
            test_file.write(header_line)
        test_file.write(bytearray(rc4cipher.encrypted_list))
    decrypted_file = rc4cipher.decrypt(encrypted_file)
    with open("viewable_decrypted.ppm", 'wba') as test_file:
        for header_line in img_header[0:3]:
            test_file.write(header_line)
        test_file.write(bytearray(rc4cipher.decrypted_list))
    headerless_img.close()
    encrypted_file.close()
    decrypted_file.close()
