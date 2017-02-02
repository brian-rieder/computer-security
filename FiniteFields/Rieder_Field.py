#!/usr/bin/env python3

# Finite Fields
# By: Brian Rieder
__author__ = 'brieder'

import sys

"""
Theory Questions:
1) Show whether or not the set of remainders Z_12 forms a group with either one of the modulo addition or modulo
   multiplication operations.
   Answer:
   In order to be a group, a set of numbers must be:
   a) Closed with respect to the operation:
      Given a, b within Z_12, a+b (mod 12) is still a member of the set Z_12 by definition of modulus.
   b) Associative with respect to the operation:
      Given a, b, c within Z_12, a+(b+c) == (a+b)+c by definition of addition.
   c) Must have a unique identity element:
      Given any element a within Z_12, a+0=0+a=a, therefore Z_12 has identity element 0 under addition.
   d) Must have a unique inverse element:
      Given any element a within Z_12, there exists b within Z_12 such that a+b=0 by definition of modulo addition.
   Therefore, Z_12 forms a group with modulo addition.

2) List all the steps involved in computing gcd(1344, 752) using Euclid's algorithm and Stein's algorithm.
    Euclid's algorithm:     Stein's algorithm:
    gcd(1344, 752)          gcd(1344, 752)          # gcd(u, v), both even: 2 * gcd(u/2, v/2)
        = gcd(752, 592)         = 2 * gcd(672, 376) # both even: 2 * gcd(u/2, v/2)
        = gcd(592, 160)         = 4 * gcd(336, 188) # both even: 2 * gcd(u/2, v/2)
        = gcd(160, 112)         = 8 * gcd(168, 94)  # both even: 2 * gcd(u/2, v/2)
        = gcd(112, 48)          = 16 * gcd(84, 47)  # u is even, v is odd: gcd(u/2, v)
        = gcd(48, 16)           = 16 * gcd(42, 47)  # u is even, v is odd: gcd(u/2, v)
        = gcd(16, 0)            = 16 * gcd(21, 47)  # both odd, u < v: gcd((v-u)/2, u)
                                = 16 * gcd(13, 21)  # both odd, u < v: gcd((v-u)/2, u)
                                = 16 * gcd(4, 13)   # u is even, v is odd: gcd(u/2, v)
                                = 16 * gcd(2, 13)   # u is even, v is odd: gcd(u/2, v)
                                = 16 * gcd(1, 13)   # both odd, u < v: gcd((v-u)/2, u)
                                = 16 * gcd(6, 1)    # u is even, v is odd: gcd(u/2, v)
                                = 16 * gcd(3, 1)    # both odd, u > v: gcd((u-v)/2, v)
                                = 16 * gcd(1, 1)    # u = v, finished
    The GCD of 1344 and 752 is 16 according to both algorithms.

3) Use the extended Euclid's algorithm to compute by hand the multiplicative inverse of 21 in Z_34. List all the steps.
    gcd(21, 34)
        = gcd(34, 21)   # 21 = 1*21 + 0*34
        = gcd(21, 13)   # 13 = 1*34 - 1*21
        = gcd(13, 8)    #  8 = 1*21 - 1*13
                        #    = 1*21 - 1*(1*34 - 1*21)
                        #    = 2*21 - 1*34
        = gcd(8, 5)     #  5 = 1*13 - 1*8
                        #    = 1*(1*34 - 1*21) - 1*(2*21 - 1*34)
                        #    = 2*34 - 3*21
        = gcd(5, 3)     #  3 = 1*8 - 1*5
                        #    = 1*(2*21 - 1*34) - 1*(2*34 - 3*21)
                        #    = 5*21 - 3*34
        = gcd(3, 2)     #  2 = 1*5 - 1*3
                        #    = 1*(2*34 - 3*21) - 1*(5*21 - 3*34)
                        #    = 5*34 - 8*21
        = gcd(2, 1)     #  1 = 1*3 - 1*2
                        #    = 1*(5*21 - 3*34) - 1*(5*34 - 8*21)
                        #    = 13*21 - 8*34
    The multiplicative inverse of 21 mod 34 is 13.


4) Find the multiplicative inverses of all non-zero elements in Z_18 (if an element doesn't have a multiplicative
   inverse, list it as such.
   ___________________________________________________________________________________________________
  |         |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
  | Element |  0 |  1 |  2 |  3 |  4 |  5 |  6 |  7 |  8 |  9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 |
  |_________|____|____|____|____|____|____|____|____|____|____|____|____|____|____|____|____|____|____|
  |         |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
  | M. Inv. | -- |  1 | -- | -- | -- | 11 | -- | 13 | -- | -- | -- |  5 | -- |  7 | -- | -- | -- | 17 |
  |_________|____|____|____|____|____|____|____|____|____|____|____|____|____|____|____|____|____|____|

5) Show with a couple of examples that x and y are not unique for any two fixed integers, a and b, in Bezout's identity.
    Bezout's Identity: gcd(a, b) = a*x + b*y
    gcd(12, 9) = 3
               = 1*12 - 1*9
               = 3*9 - 2*12
               = 4*12 - 5*9
    gcd(8, 6)  = 2
               = 1*8 - 1*6
               = 3*6 - 2*8
               = 4*8 - 5*9
    As there are multiple linear combinations of x and y respectively multiplied into a and b, x and y are not unique.


6) Find integers x such that:
    The shown integers are all integers within Z_n where n is the modulus provided.
    a)  8x === 6 (mod 22)
        x = 6, 20
    b)  6x === 3 (mod 19)
        x = 10
    c) 25x === 9 (mod  7)
        No integer exists as the result, 9, is not within Z_7.
"""

# Programming Assignment
def has_MI(num, mod):
    """
    Determines whether the input number has a multiplicative inverse under the input modulus.
    :param num: Number to check
    :param mod: Modulus under which MI may exit
    :return: Boolean indicating if num has a MI under mod
    """
    x, x_old = 0, 1
    y, y_old = 1, 0
    while mod:
        q = num // mod
        num, mod = mod, num % mod
        x, x_old = x_old - q * x, x
        y, y_old = y_old - q * y, y
    if num != 1:
        return False
    else:
        return True


if __name__ == '__main__':
    # Usage:
    # 1) Input modulus value to check via command line: ./Rieder_Field.py <modulus integer>
    # 2) When no command line arguments are supplied, the script will prompt the user.
    # Outputs to 'output.txt' per specification
    if len(sys.argv) == 1:
        modulus = int(input("Enter a modulus to check field vs. ring: "))
    elif len(sys.argv) == 2:
        modulus = int(sys.argv[1])
    else:
        raise ValueError("Error: Maximum of one command line argument.")
    output_file = open("output.txt", 'w')
    for val in range(1, modulus):
        if not has_MI(val, modulus):
            output_file.write("ring\n")
            sys.exit()
    output_file.write("field\n")
    output_file.close()

