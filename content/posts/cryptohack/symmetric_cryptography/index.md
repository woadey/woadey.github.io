---
title: "CryptoHack: Symmetric Cryptography"
date: 2022-11-08T22:07:33-07:00
draft: true
summary: "Writeups for CryptoHack's Symmetric Cryptography Course"
description: "Writeups for CryptoHack's [Symmetric Cryptography Course](https://cryptohack.org/courses/symmetric/course_details/)"
categories: ["cryptohack"]
tags: ["crypto", "aes"]
keywords: ["cryptohack","crypto","modular","arithmetic"]
cover:
    image: "images/symmetric.png"
---

## Keyed Permutations
> AES, like all good block ciphers, performs a "keyed permutation". This means that it maps every possible input block to a unique output block, with a key determining which permutation to perform.
>
>Using the same key, the permutation can be performed in reverse, mapping the output block back to the original input block. It is important that there is a one-to-one correspondence between input and output blocks, otherwise we wouldn't be able to rely on the ciphertext to decrypt back to the same plaintext we started with.
>What is the mathematical term for a one-to-one correspondence?

### Solution
**flag:** `crypto{bijection}`

## Resisting Bruteforce
> If a block cipher is secure, there should be no way for an attacker to distinguish the output of AES from a [random permutation](https://en.wikipedia.org/wiki/Pseudorandom_permutation) of bits. Furthermore, there should be no better way to undo the permutation than simply bruteforcing every possible key. That's why academics consider a cipher theoretically "broken" if they can find an attack that takes fewer steps to perform than bruteforcing the key, even if that attack is practically infeasible.
>
>It turns out that there is [an attack](https://en.wikipedia.org/wiki/Biclique_attack) on AES that's better than bruteforce, but only slightly – it lowers the security level of AES-128 down to 126.1 bits, and hasn't been improved on for over 8 years. Given the large "security margin" provided by 128 bits, and the lack of improvements despite extensive study, it's not considered a credible risk to the security of AES. But yes, in a very narrow sense, it "breaks" AES.
>
>Finally, while quantum computers have the potential to completely break popular public-key cryptosystems like RSA via [Shor's algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm), they are thought to only cut in half the security level of symmetric cryptosystems via [Grover's algorithm](https://en.wikipedia.org/wiki/Grover's_algorithm). This is one reason why people recommend using AES-256, despite it being less performant, as it would still provide a very adequate 128 bits of security in a quantum future.
>
>What is the name for the best single-key attack against AES?

### Solution
**flag:** `crypto{biclique}`

## Structure of AES
>To achieve a keyed permutation that is infeasible to invert without the key, AES applies a large number of ad-hoc mixing operations on the input. This is in stark contrast to public-key cryptosystems like RSA, which are based on elegant individual mathematical problems. AES is much less elegant, but it's very fast.
>
>At a high level, AES-128 begins with a "key schedule" and then runs 10 rounds over a state. The starting state is just the plaintext block that we want to encrypt, represented as a 4x4 matrix of bytes. Over the course of the 10 rounds, the state is repeatedly modified by a number of invertible transformations.
>
>Here's an overview of the phases of AES encryption:
> 
> 1. **KeyExpansion** or Key Schedule
> 
> From the 128 bit key, 11 separate 128 bit "round keys" are derived: one to be used in each AddRoundKey step.
> 
> 2. **Initial key addition**
> 
> *AddRoundKey* - the bytes of the first round key are XOR'd with the bytes of the state.
> 
> 3. **Round** - this phase is looped 10 times, for 9 main rounds plus one "final round"
> 
>  a) *SubBytes* - each byte of the state is substituted for a different byte according to a lookup table ("S-box").
> 
>  b) *ShiftRows* - the last three rows of the state matrix are transposed—shifted over a column or two or three.
> 
>  c) *MixColumns* - matrix multiplication is performed on the columns of the state, combining the four bytes in each column. This is skipped in the final round.
> 
>  d) *AddRoundKey* - the bytes of the current round key are XOR'd with the bytes of the state.
> 
> Included is a `bytes2matrix` function for converting our initial plaintext block into a state matrix. Write a `matrix2bytes` function to turn that matrix back into bytes, and submit the resulting plaintext as the flag.
>
> Challenge files:
> - matrix.py
>
> Resources:
>  - [YouTube: AES Rijndael Cipher explained as a Flash animation](https://www.youtube.com/watch?v=gP4PqVGudtg)

*file: matrix.py*
```python
def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    ????

matrix = [
    [99, 114, 121, 112],
    [116, 111, 123, 105],
    [110, 109, 97, 116],
    [114, 105, 120, 125],
]

print(matrix2bytes(matrix))
```

### Solution
```python
def matrix2bytes(matrix):
    return "".join([chr(n) for lst in matrix for n in lst])
```
```shell {linenos=false}
> print(matrix2bytes(matrix))
crypto{inmatrix}
```

Alternative solution(s):
```python
# source: CryptoHack user @Robin_Jadoul

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return bytes(sum(matrix, []))
```

**flag:** `crypto{inmatrix}`

## Round Keys
> We're going to skip over the finer details of the KeyExpansion phase for now. The main point is that it takes in our 16 byte key and produces 11 4x4 matrices called "round keys" derived from our initial key. These round keys allow AES to get extra mileage out of the single key that we provided.
>
>The **initial key addition** phase, which is next, has a single *AddRoundKey* step. The *AddRoundKey* step is straightforward: it XORs the current state with the current round key.
>
>*AddRoundKey* also occurs as the final step of each round. *AddRoundKey* is what makes AES a "keyed permutation" rather than just a permutation. It's the only part of AES where the key is mixed into the state, but is crucial for determining the permutation that occurs.
>
>As you've seen in previous challenges, XOR is an easily invertible operation if you know the key, but tough to undo if you don't. Now imagine trying to recover plaintext which has been XOR'd with 11 different keys, and heavily jumbled between each XOR operation with a series of substitution and transposition ciphers. That's kinda what AES does! And we'll see just how effective the jumbling is in the next few challenges.
> 
> Complete the `add_round_key` function, then use the `matrix2bytes` function to get your next flag.
> 
> Challenge files:
>  - add_round_key.py

*file: add_round_key.py*
```python
state = [
    [206, 243, 61, 34],
    [171, 11, 93, 31],
    [16, 200, 91, 108],
    [150, 3, 194, 51],
]

round_key = [
    [173, 129, 68, 82],
    [223, 100, 38, 109],
    [32, 189, 53, 8],
    [253, 48, 187, 78],
]


def add_round_key(s, k):
    ???


print(add_round_key(state, round_key))
```

### Solution
```python
def add_round_key(s, k):
    return [[x^y for x,y in zip(sum(s,[]), sum(k,[]))][i:i+4] for i in range(0,16,4)]
```
or
```python
def add_round_key(s, k):
    return [[s_val^k_val for s_val, k_val in zip(s_lst,k_lst)] for s_lst, k_lst in zip(s, k)]
```

```shell {linenos=false}
> add_round_key(state, round_key)
[[99, 114, 121, 112],
 [116, 111, 123, 114],
 [48, 117, 110, 100],
 [107, 51, 121, 125]]
> print(matrix2bytes(add_round_key(state, round_key)))
crypto{r0undk3y}
```

**flag:** `crypto{r0undk3y}`

## Confusion through Substitution
> The first step of each AES round is SubBytes. This involves taking each byte of the state matrix and substituting it for a different byte in a preset 16x16 lookup table. The lookup table is called a "Substitution box" or "S-box" for short, and can be perplexing at first sight. Let's break it down.
> 
> In 1945 American mathematician Claude Shannon published a groundbreaking paper on Information Theory. It identified "confusion" as an essential property of a secure cipher. "Confusion" means that the relationship between the ciphertext and the key should be as complex as possible. Given just a ciphertext, there should be no way to learn anything about the key.
> 
> If a cipher has poor confusion, it is possible to express a relationship between ciphertext, key, and plaintext as a linear function. For instance, in a Caesar cipher, `ciphertext = plaintext + key`. That's an obvious relation, which is easy to reverse. More complicated linear transformations can be solved using techniques like Gaussian elimination. Even low-degree polynomials, e.g. an equation like `x^4 + 51x^3 + x`, can be solved efficiently using [algebraic methods](https://math.stackexchange.com/a/1078515). However, the higher the degree of a polynomial, generally the harder it becomes to solve – it can only be approximated by a larger and larger amount of linear functions.
> 
> The main purpose of the S-box is to transform the input in a way that is resistant to being approximated by linear functions. S-boxes are  aiming for high non-linearity, and while AES's one is not perfect, it's pretty close. The fast lookup in an S-box is a shortcut for performing a very nonlinear function on the input bytes. This function involves taking the modular inverse in the [Galois field 2**8](https://www.samiam.org/galois.html) and then applying an affine transformation which has been tweaked for maximum confusion. The simplest way to express the function is through the following high-degree polynomial:
> 
> diagram showing S-Box equation
> 
> To make the S-box, the function has been calculated on all input values from 0x00 to 0xff and the outputs put in the lookup table.
> 
> Implement `sub_bytes`, send the state matrix through the inverse S-box and then convert it to bytes to get the flag.
> 
> Challenge files:
>   - sbox.py

*file: sbox.py*
```python
s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

state = [
    [251, 64, 182, 81],
    [146, 168, 33, 80],
    [199, 159, 195, 24],
    [64, 80, 182, 255],
]


def sub_bytes(s, sbox=s_box):
    ???


print(sub_bytes(state, sbox=inv_s_box))
```

### Solution
```python
def sub_bytes(s, sbox=s_box):
    return bytes([sbox[x] for x in sum(s,[])])
```
```shell {linenos=false}
> sub_bytes(state, inv_s_box)
b'crypto{l1n34rly}'
```

**flag:** `crypto{l1n34rly}`

## Diffusion through Permutation
>We've seen how S-box substitution provides confusion. The other crucial property described by Shannon is "diffusion". This relates to how every part of a cipher's input should spread to every part of the output.
>
>Substitution on its own creates non-linearity, however it doesn't distribute it over the entire state. Without diffusion, the same byte in the same position would get the same transformations applied to it each round. This would allow cryptanalysts to attack each byte position in the state matrix separately. We need to alternate substitutions by scrambling the state (in an invertible way) so that substitutions applied on one byte influence all other bytes in the state. Each input into the next S-box then becomes a function of multiple bytes, meaning that with every round the algebraic complexity of the system increases enormously.
>
>The *ShiftRows* and *MixColumns* steps combine to achieve this. They work together to ensure every byte affects every other byte in the state within just two rounds.
>
>*ShiftRows* is the most simple transformation in AES. It keeps the first row of the state matrix the same. The second row is shifted over one column to the left, wrapping around. The third row is shifted two columns, the fourth row by three. Wikipedia puts it nicely: "the importance of this step is to avoid the columns being encrypted independently, in which case AES degenerates into four independent block ciphers."
>
>*MixColumns* is more complex. It performs Matrix multiplication in Rijndael's Galois field between the columns of the state matrix and a preset matrix. Each single byte of each column therefore affects all the bytes of the resulting column. The implementation details are nuanced; [this page](https://www.samiam.org/mix-column.html) and [Wikipedia](https://en.wikipedia.org/wiki/Rijndael_MixColumns) do a good job of covering them.
>
>We've provided code to perform *MixColumns* and the forward *ShiftRows* operation. After implementing `inv_shift_rows`, take the state, run `inv_mix_columns` on it, then `inv_shift_rows`, convert to bytes and you will have your flag.
>
>Challenge files:
>  - diffusion.py

*file: diffusion.py*
```python
def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def inv_shift_rows(s):
    ???


# learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


def inv_mix_columns(s):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)


state = [
    [108, 106, 71, 86],
    [96, 62, 38, 72],
    [42, 184, 92, 209],
    [94, 79, 8, 54],
]
```

### Solution
```python
def inv_shift_rows(s):
    s[1][1], s[2][1], s[3][1], s[0][1] = s[0][1], s[1][1], s[2][1], s[3][1]
    s[2][2], s[3][2], s[0][2], s[1][2] = s[0][2], s[1][2], s[2][2], s[3][2]
    s[3][3], s[0][3], s[1][3], s[2][3] = s[0][3], s[1][3], s[2][3], s[3][3]
```

```shell {linenos=false}
> inv_mix_columns(state)
> state
[[99, 111, 102, 125],
 [116, 102, 82, 112],
 [49, 51, 121, 100],
 [115, 114, 123, 85]]
> inv_shift_rows(state)
> state
[[99, 114, 121, 112],
 [116, 111, 123, 100],
 [49, 102, 102, 85],
 [115, 51, 82, 125]]
> matrix2bytes(state)
b'crypto{d1ffUs3R}'
 ```

 **flag:** `crypto{d1ffUs3R}`

## Bringing It All Together
>Apart from the **KeyExpansion** phase, we've sketched out all the components of AES. We've shown how *SubBytes* provides confusion and *ShiftRows* and *MixColumns* provide diffusion, and how these two properties work together to repeatedly circulate non-linear transformations over the state. Finally, *AddRoundKey* seeds the key into this substitution-permutation network, making the cipher a keyed permutation.
>
>Decryption involves performing the steps described in the "Structure of AES" challenge in reverse, applying the inverse operations. Note that the KeyExpansion still needs to be run first, and the round keys will be used in reverse order. *AddRoundKey* and its inverse are identical as XOR has the self-inverse property.
>
>We've provided the key expansion code, and ciphertext that's been properly encrypted by AES-128. Copy in all the building blocks you've coded so far, and complete the `decrypt` function that implements the steps shown in the diagram. The decrypted plaintext is the flag.
>
>Yes, you can cheat on this challenge, but where's the fun in that?
>
>The code used in these exercises has been taken from Bo Zhu's super simple Python AES implementation, so we've reproduced the license here.
>
>Challenge files:
>  - aes_decrypt.py
>  - LICENSE
>
>Resources:
>  - [Rolling your own crypto: Everything you need to build AES from scratch](https://github.com/francisrstokes/githublog/blob/main/2022/6/15/rolling-your-own-crypto-aes.md)

*file: aes_decrypt.py*
```python
N_ROUNDS = 10

key        = b'\xc3,\\\xa6\xb5\x80^\x0c\xdb\x8d\xa5z*\xb6\xfe\\'
ciphertext = b'\xd1O\x14j\xa4+O\xb6\xa1\xc4\x08B)\x8f\x12\xdd'



def expand_key(master_key):
    """
    Expands and returns a list of key matrices for the given master_key.
    """

    # Round constants https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
    r_con = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
        0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )

    # Initialize round keys with raw key material.
    key_columns = bytes2matrix(master_key)
    iteration_size = len(master_key) // 4

    # Each iteration has exactly as many columns as the key material.
    i = 1
    while len(key_columns) < (N_ROUNDS + 1) * 4:
        # Copy previous word.
        word = list(key_columns[-1])

        # Perform schedule_core once every "row".
        if len(key_columns) % iteration_size == 0:
            # Circular shift.
            word.append(word.pop(0))
            # Map to S-BOX.
            word = [s_box[b] for b in word]
            # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
            word[0] ^= r_con[i]
            i += 1
        elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
            # Run word through S-box in the fourth iteration when using a
            # 256-bit key.
            word = [s_box[b] for b in word]

        # XOR with equivalent word from previous iteration.
        word = bytes(i^j for i, j in zip(word, key_columns[-iteration_size]))
        key_columns.append(word)

    # Group key words in 4x4 byte matrices.
    return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]


def decrypt(key, ciphertext):
    round_keys = expand_key(key) # Remember to start from the last round key and work backwards through them when decrypting

    # Convert ciphertext to state matrix
    
    # Initial add round key step

    for i in range(N_ROUNDS - 1, 0, -1):
        pass # Do round

    # Run final round (skips the InvMixColumns step)

    # Convert state matrix to plaintext

    return plaintext


# print(decrypt(key, ciphertext))
```

### Solution
```python
from Crypto.Util.number import bytes_to_long

N_ROUNDS = 10

key        = b'\xc3,\\\xa6\xb5\x80^\x0c\xdb\x8d\xa5z*\xb6\xfe\\'
ciphertext = b'\xd1O\x14j\xa4+O\xb6\xa1\xc4\x08B)\x8f\x12\xdd'

s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

def expand_key(master_key):
    """
    Expands and returns a list of key matrices for the given master_key.
    """

    # Round constants https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
    r_con = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
        0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )

    # Initialize round keys with raw key material.
    key_columns = bytes2matrix(master_key)
    iteration_size = len(master_key) // 4

    # Each iteration has exactly as many columns as the key material.
    i = 1
    while len(key_columns) < (N_ROUNDS + 1) * 4:
        # Copy previous word.
        word = list(key_columns[-1])

        # Perform schedule_core once every "row".
        if len(key_columns) % iteration_size == 0:
            # Circular shift.
            word.append(word.pop(0))
            # Map to S-BOX.
            word = [s_box[b] for b in word]
            # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
            word[0] ^= r_con[i]
            i += 1
        elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
            # Run word through S-box in the fourth iteration when using a
            # 256-bit key.
            word = [s_box[b] for b in word]

        # XOR with equivalent word from previous iteration.
        word = bytes(i^j for i, j in zip(word, key_columns[-iteration_size]))
        key_columns.append(word)

    # Group key words in 4x4 byte matrices.
    return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]

def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    return bytes(sum(matrix, []))

def add_round_key(s, k):
    return [[s_val^k_val for s_val, k_val in zip(s_lst,k_lst)] for s_lst, k_lst in zip(s, k)]

def inv_shift_rows(s):
    s[1][1], s[2][1], s[3][1], s[0][1] = s[0][1], s[1][1], s[2][1], s[3][1]
    s[2][2], s[3][2], s[0][2], s[1][2] = s[0][2], s[1][2], s[2][2], s[3][2]
    s[3][3], s[0][3], s[1][3], s[2][3] = s[0][3], s[1][3], s[2][3], s[3][3]

def sub_bytes(s, sbox=s_box):
    return [[int(sbox[a]) for a in row] for row in s]

# learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)

def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])

def inv_mix_columns(s):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)

def decrypt(key, ciphertext):
    round_keys = expand_key(key) # Remember to start from the last round key and work backwards through them when decrypting

    # Convert ciphertext to state matrix
    state = bytes2matrix(ciphertext)
    
    # Initial add round key step
    state = add_round_key(state, round_keys[-1])

    for i in range(N_ROUNDS - 1, 0, -1):
        inv_shift_rows(state)
        state = sub_bytes(state, inv_s_box)
        state = add_round_key(state, round_keys[i])
        inv_mix_columns(state)

    # Run final round (skips the InvMixColumns step)
    inv_shift_rows(state)
    state = sub_bytes(state, inv_s_box)
    state = add_round_key(state, round_keys[0])

    # Convert state matrix to plaintext
    plaintext = matrix2bytes(state)

    return plaintext
```

```shell {linenos=false}
> print(decrypt(key,ciphertext))
b'crypto{MYAES128}'
```

**flag:** `crypto{MYAES128}`

## Modes of Operation Starter
>The previous set of challenges showed how AES performs a keyed permutation on a block of data. In practice, we need to encrypt messages much longer than a single block. A mode of operation describes how to use a cipher like AES on longer messages.
>
>All modes have serious weaknesses when used incorrectly. The challenges in this category take you to a different section of the website where you can interact with APIs and exploit those weaknesses. Get yourself acquainted with the interface and use it to take your next flag!
>
>Play at http://aes.cryptohack.org/block_cipher_starter

### Solution
1. Visit http://aes.cryptohack.org/block_cipher_starter
2. Visit https://aes.cryptohack.org//block_cipher_starter/encrypt_flag/
```{linenos=false}
{"ciphertext":"1b36a55b687f21f73fe0bed721c1a5c305716a9a1c1745d50a39e0ae8f2fb9ba"}
```
3. Decrypt ciphertext
![decrypt](images/decrypt.png#center)
4. Hex Decode
![decode](images/decode.png#center)

**flag:** `crypto{bl0ck_c1ph3r5_4r3_f457_!}`

## Passwords as Keys
>It is essential that keys in symmetric-key algorithms are random bytes, instead of passwords or other predictable data. The random bytes should be generated using a cryptographically-secure pseudorandom number generator (CSPRNG). If the keys are predictable in any way, then the security level of the cipher is reduced and it may be possible for an attacker who gets access to the ciphertext to decrypt it.
>
>Just because a key looks like it is formed of random bytes, does not mean that it necessarily is. In this case the key has been derived from a simple password using a hashing function, which makes the ciphertext crackable.
>
>For this challenge you may script your HTTP requests to the endpoints, or alternatively attack the ciphertext offline. Good luck!
>
>Play at http://aes.cryptohack.org/passwords_as_keys

### Solution
```python
import requests
import hashlib
from time import sleep
from Crypto.Cipher import AES

# Get Ciphertext
url = 'http://aes.cryptohack.org/passwords_as_keys'
r = requests.get(f"{url}/encrypt_flag")
ct = r.json()['ciphertext']
print(f"Ciphertext: {ct}")

# Get word list
r = requests.get("https://gist.githubusercontent.com/wchargin/8927565/raw/d9783627c731268fb2935a731a618aa8e95cf465/words")
words = r.content.split(b'\n')

# Brute password
for word in words:
    key = hashlib.md5(word).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        pt = cipher.decrypt(bytes.fromhex(ct))
        if b"crypto{" in pt:
            print(f"Plaintext: {pt.decode()}")
    except:
        continue
```

**flag:** `crypto{k3y5__r__n07__p455w0rdz?}`

## ECB Oracle
>ECB is the most simple mode, with each plaintext block encrypted entirely independently. In this case, your input is prepended to the secret flag and encrypted and that's it. We don't even provide a decrypt function. Perhaps you don't need a padding oracle when you have an "ECB oracle"?
>
>Play at http://aes.cryptohack.org/ecb_oracle

### Solution
This problem was a bit difficult for me to solve. The first step in understanding it was looking more into how the `pad` function actually works in the backend of `pycryptodome`. This is more easily demonstrated through an example.

```shell {linenos=false}
> from Crypto.Util.Padding import pad
> [pad(b'?'*i, 16) for i in range(1,17)] # We want to see 1-16, so we set the range to 17 since it doesn't include the last value.
[b'?\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f',
 b'??\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e',
 b'???\r\r\r\r\r\r\r\r\r\r\r\r\r',
 b'????\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c',
 b'?????\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b',
 b'??????\n\n\n\n\n\n\n\n\n\n',
 b'???????\t\t\t\t\t\t\t\t\t',
 b'????????\x08\x08\x08\x08\x08\x08\x08\x08',
 b'?????????\x07\x07\x07\x07\x07\x07\x07',
 b'??????????\x06\x06\x06\x06\x06\x06',
 b'???????????\x05\x05\x05\x05\x05',
 b'????????????\x04\x04\x04\x04',
 b'?????????????\x03\x03\x03',
 b'??????????????\x02\x02',
 b'???????????????\x01',
 b'????????????????\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10']
 ```

 When the amount of `?`s we provide is less than the `block_size` of 16, padding will be added. However, if 16 bytes (or `?`s) are provided, the `pad` function will create a new block (2 blocks of 16 bytes, totalling to 32 bytes in length). Therefore, if we give a bunch of garbage, we can leak the length of the flag. 

 TL;DR: we can measure the amount of bytes we send in alongside the amount of blocks that get generated to determine the flag length. So, if we send in `x-1` bytes and have 2 blocks (32 bytes total), then send in `x` bytes and have 3 blocks (48 bytes total), we know: 
 ```{linenos=false}
 flag_length = 2 blocks * 16 bytes/block - x bytes => 32 bytes - x bytes
 ```

 Time to script...

 ```python
import string
import requests

def encrypt(plainhex):
    r = requests.get(f"https://aes.cryptohack.org/ecb_oracle/encrypt/{plainhex}")
    return bytes.fromhex(r.json()['ciphertext'])

ciphers = []
for i in range(1,17):
    garbage = i*b'?'.hex()
    ct = encrypt(garbage)
    ciphers.append(ct)
    print(f"Garbage ({len(garbage)//2} bytes): {bytes.fromhex(garbage).decode()}")
    print(f"Ciphertext ({len(ct.hex())//2} bytes): {ct.hex()}")
 ```

 ```{linenos=false}
Garbage (1 bytes): ?
Ciphertext (32 bytes): 341dd0bf293efbc386baa0450a9f7a121d91b08cbd0a3ff55d6225e7f2cb1fe1
Garbage (2 bytes): ??
Ciphertext (32 bytes): c7404a9325a0b5bd6f663638f86f6d14133cfd98ad547f6a1dae2cdccac36bda
Garbage (3 bytes): ???
Ciphertext (32 bytes): 1e46817be36af1d0d263fed68ab2b3b440b0f25961b3330f4880effcdd1d9372
Garbage (4 bytes): ????
Ciphertext (32 bytes): 700b70280d82306f6b577da0e70914003775fe4513f275eeb4a20548db2b1372
Garbage (5 bytes): ?????
Ciphertext (32 bytes): 043d72cd0c91d09ee654031196f6a203f0aaaa9734688f65f110768d242965f2
Garbage (6 bytes): ??????
Ciphertext (32 bytes): dd90d7562c5d17c5ff323f1a024483749f1d9ea23fc3f0857e80d9254d053b99
Garbage (7 bytes): ???????
Ciphertext (48 bytes): d32166eeaa47575cf04ae32526b6006c1f227170511203bbb211a703905f9e5128ae38bc1312435b814108836328262a
Garbage (8 bytes): ????????
Ciphertext (48 bytes): 9eaa653b150e6218b56d887fb99d00f21206ed1975a928fe0813952f43171080b6800d8b95758d3bf16d0f75ca9f38e8
Garbage (9 bytes): ?????????
Ciphertext (48 bytes): 7a987178f47d51a9d650fdd312580bf50e5eaa21119c631ae8304d9d2c1ef310593c7d830f153c8a4b7f41c116065d73
Garbage (10 bytes): ??????????
Ciphertext (48 bytes): 66a3abc4b4b82020586064a647d7fa75e1434b90c1f8633f9818265dfff40e08c9dd5d6a2703d3beb1def6e688083f3a
Garbage (11 bytes): ???????????
Ciphertext (48 bytes): 0fd571c8e551af19d186a30c9b3c02034cc4a08218ed3d4aead3c49d2c49e5b5ed8db991b61458ce267a94b891a472fb
Garbage (12 bytes): ????????????
Ciphertext (48 bytes): 12d380f787bdbc1bc7a4b8619f45609af2f1b66e09e912eff09384648f453f3db11abf8572ab7a34347ada3026bf0911
Garbage (13 bytes): ?????????????
Ciphertext (48 bytes): ae7db02691622c4562866713fa013c5cee268318401e6c194260a8ffa3d2df71190f2b09607b5764d577d4d5569b9059
Garbage (14 bytes): ??????????????
Ciphertext (48 bytes): 5f26e6ffabb6962705a174ac4b463bcc7bd036db83a337f9f4f867dd5691e1f7fd105ad78e0e6fa84f694743dd59cc94
Garbage (15 bytes): ???????????????
Ciphertext (48 bytes): eed4350b17297b157330c401581ac453a6734bcc83eace3a107321af7775026b7d715d5c670622e24c462ae108288f25
Garbage (16 bytes): ????????????????
Ciphertext (48 bytes): da572df43b1a6bd8ad66da297d64c445bea177bc81b326eef475195dee42ba6c2eb3958aa4a3fa0d49789f5152a4eed2
```

As shown above, we can see that when 7 bytes of garbage are sent in, a new block is made. This meas our flag must be `32-7 = 25 bytes`.

```shell {linenos=false}
> flag_len = [len(i.hex())//2 - x - 2 for x, (i,j) in enumerate(zip(ciphers,ciphers[1:])) if len(j.hex())>len(i.hex())][0]
25
```

From here, we know that the flag will need be held within 2 blocks. If we want to leak the flag, we will need 4 blocks total (2 for garbage and leaking + 2 for holding the flag and padding) totalling to 64 bytes. To make more sense of how this works, let's start with leaking a few bytes manually. 

From previous challenges, let's assume the flag does adhere to the format `crypto{...}`. When scripting, its easy to check all possible bytes, but since this is an example and its manual, let's be smart and guess the first byte is `c`. From above, we can see: 

```{linenos=false}
Garbage (15 bytes): ???????????????
Ciphertext (48 bytes): eed4350b17297b157330c401581ac453a6734bcc83eace3a107321af7775026b7d715d5c670622e24c462ae108288f25
```

As we remember, each block is 16 bytes. Since we only sent in 15 bytes and this plaintext is prepended to the flag, we *know* that the next byte (16th byte) has to be the first byte of the flag. We also know that each block is independent and will have its own ciphertext. This means that if the 16th byte is the same as the first byte of the flag, we will get the *same* ciphertext for block 1. For example:

```{linenos=false}
Garbage (15 bytes): ???????????????
Ciphertext (48 bytes): eed4350b17297b157330c401581ac453  a6734bcc83eace3a107321af7775026b  7d715d5c670622e24c462ae108288f25

Garbage (15 bytes) + 'c' (1 byte): ???????????????c
Ciphertext (48 bytes): eed4350b17297b157330c401581ac453  bea177bc81b326eef475195dee42ba6c  2eb3958aa4a3fa0d49789f5152a4eed2
``` 

As we can see, the first block of ciphertext for each payload is the same. `eed4350b17297b157330c401581ac453 == eed4350b17297b157330c401581ac453`

Let's try it again for the sake of clarity. Now that we know the first letter of the flag is `c`, we need to reduce the amount of garbage we send in to 14 bytes (`14 + len('c') = 15`) so there is only byte we need to guess. We can try `r` due to the flag format.

```{linenos=false}
Garbage (14 bytes) + 'c' (1 byte): ??????????????c
Ciphertext (48 bytes): 5f26e6ffabb6962705a174ac4b463bcc  7bd036db83a337f9f4f867dd5691e1f7  fd105ad78e0e6fa84f694743dd59cc94

Garbage (14 bytes) + 'c' (1 byte) + 'r' (1 byte): ??????????????cr
Ciphertext (48 bytes): 5f26e6ffabb6962705a174ac4b463bcc  bea177bc81b326eef475195dee42ba6c  2eb3958aa4a3fa0d49789f5152a4eed2
```

That's it basically. Just script this process!

```python
import string
import requests

def encrypt(plainhex):
    r = requests.get(f"https://aes.cryptohack.org/ecb_oracle/encrypt/{plainhex}")
    return bytes.fromhex(r.json()['ciphertext'])

ciphers = []
for i in range(1,17):
    garbage = i*b'?'.hex()
    ct = encrypt(garbage)
    ciphers.append(ct)
    print(f"Garbage ({len(garbage)//2} bytes): {bytes.fromhex(garbage).decode()}")
    print(f"Ciphertext ({len(ct.hex())//2} bytes): {ct.hex()}")

# Calculate flag length (easier visually)
flag_len = [len(i.hex())//2 - x - 2 for x, (i,j) in enumerate(zip(ciphers,ciphers[1:])) if len(j.hex())>len(i.hex())][0]

# Put likely strings and letters at the beginning - remove duplicates
alpha = list(dict.fromkeys("crypto{eainshr_}" + string.ascii_lowercase + string.digits + string.ascii_uppercase))
flag = b""
print("Brute forcing flag...\n")
for i in range(31, 31-flag_len, -1):
    for char in alpha:
        char = char.encode()
        ct = encrypt((i*b"?"+flag+char).hex())[:32]
        exp = encrypt((i*b"?").hex())[:32]
        if ct == exp:
            flag += char
            print(f"{char.decode()}", flush=True, end='')
            break
```

**flag:** `crypto{p3n6u1n5_h473_3cb}`

## ECB CBC WTF
>Here you can encrypt in CBC but only decrypt in ECB. That shouldn't be a weakness because they're different modes... right?
>
>Play at http://aes.cryptohack.org/ecbcbcwtf