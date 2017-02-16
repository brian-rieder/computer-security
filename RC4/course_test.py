__author__ = 'brieder'

import filecmp

from hw05 import *
rc4cipher = RC4('key string')
original_image = open("winterTownNoHeader.ppm", 'r')
encrypted_image = rc4cipher.encrypt(original_image)
decrypted_file = rc4cipher.decrypt(encrypted_image)
# if original_image == decrypted_file:  # THIS IS NOT HOW YOU COMPARE FILES, PROF. KAK...
if filecmp.cmp("winterTownNoHeader.ppm", "decryptedImage.ppm"):
    print('RC4 is awesome')
else:
    print('Hmm, something seems fishy!')
