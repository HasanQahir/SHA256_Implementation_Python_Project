import numpy as np
import math
import warnings
warnings.filterwarnings('ignore', 'overflow encountered', RuntimeWarning)

#! Initialize hash values:
#* first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19
#* We ensure the length of these variables by explicitly typing them.

h0: np.uint32 = 0x6a09e667
h1: np.uint32 = 0xbb67ae85
h2: np.uint32 = 0x3c6ef372
h3: np.uint32 = 0xa54ff53a
h4: np.uint32 = 0x510e527f
h5: np.uint32 = 0x9b05688c
h6: np.uint32 = 0x1f83d9ab
h7: np.uint32 = 0x5be0cd19

#? How these are found:
#* The first 32 bits of the fractional part (Matissa) are the same as h0
hex = math.sqrt(2).hex()
#print(hex) # 0x1.6a09e667f3bcdp+0

frac_val = hex.split('.')[1][:8]
#print('0x' + frac_val) #0x6a09e667

#! Initialize array of round constants:
#* first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311
k_const = np.array((
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2),
   dtype=np.uint32
)


#! Pre-processing (Padding):
#* Appending bits to the end of the original message to meet length requirements

def padding(message: str):
    bin_message = ""

    #Convert message to binary, 1 byte per character
    utf8_message = message.encode(encoding='utf_8')
    for char in utf8_message:
        bin_message += bin(char).lstrip('0b').zfill(8)

    #Take the converted message's length as a 64 bit int
    l_padding = bin(len(bin_message)).lstrip('0b').zfill(64)

    #SHA256 pads our string in this order
    #Account for the 64 bit int in advance as it lies at the end of the string
    bin_message += '1'
    bin_message += str("").zfill(448 - (len(bin_message) % 512))
    bin_message += l_padding

    return bin_message


#! Process the message into 512-bit chunks
#* Take slices over every 512 bits and copy into an array
def chunks_512bits(full_msg: str):
    pos = 0
    chunks: list[str] = []
    while pos < len(full_msg):
        chunks.append(full_msg[pos:pos+512])
        pos += 512
    return chunks



#! Place the 512-bit chunks into arrays of 32-bit entries
#* This chunk of the message will fit into the first 16 entires of the array
#* The rest of the array is ignored since their entries will be generated from the first 16.  
def create_msg_sch_arr(chunk: str):
    arr = np.zeros(64, dtype=object)
    for i in range(16):
        ch_pos = 32*i
        arr[i] = chunk[ch_pos:ch_pos + 32]
    
    return arr


#? Functions to manipulate our bit strings
#* Since we're not working with binary directly, we have to use string methods to manipulate them

# Righthand Bit-Rotation - shifts bits to the right by 'val' amount. Trailing bits are placed at the front of the bit string.
def rrotate(msg_sch_word: str, val: int):

    if len(msg_sch_word) != 32:
        return ValueError
    if val == 0:
        return IndexError

    val = val % 32
    rot_msg = msg_sch_word[(32 - val):32]
    return "".join([rot_msg, msg_sch_word[0:(32 - val)]])


# Righthand Bit-Shift - shifts bits to the right by 'val' amount. Trailing bits are discarded, empty spaces are filled with zeroes
def rshift(msg_sch_word: str, val: int):

    if len(msg_sch_word) != 32:
        return ValueError
    if val == 0:
        return IndexError
    
    shift_msg = msg_sch_word[0:(32 - val)]
    return shift_msg.zfill(32)


# Xor - covenient way to xor our bit strings. Not entirely ideal because it creates the nested function calls seen below
def xor(word1: str, word2: str):
    return "".join([str(int(_a) ^ int(_b)) for _a, _b in zip(word1, word2)])



#! Fill the rest of the message array
#* Takes two filled 32-bit entries and creates a new entry which is almost certainly different 
#* The bit-shifts and rotations seen below have their 'val's given by the algorithm

def extend_bitwise_op(msg_sch_arr: np.ndarray[str]):
    for i in range(16, 64):

        s0 = xor( xor( rrotate(msg_sch_arr[i - 15], 7), rrotate(msg_sch_arr[i - 15], 18)), rshift(msg_sch_arr[i - 15], 3))

        s1 = xor( xor( rrotate(msg_sch_arr[i - 2], 17), rrotate(msg_sch_arr[i - 2], 19)), rshift(msg_sch_arr[i - 2], 10))

        new_word = np.uint32(int(msg_sch_arr[i - 16], 2)) + np.uint32(int(s0, 2)) + np.uint32(int(msg_sch_arr[i - 7], 2)) + np.uint32(int(s1, 2))

        msg_sch_arr[i] = np.binary_repr(new_word, 32)
    
    return msg_sch_arr


#! Compression function main loop
#? Applied once for each 512-bit chunk of our message
#* Cycles and XORs each of the message array's entries before adding them to our h_values
#* This step makes SHA256 functionally irreversible to brute-force attacks, although length-extension can invert the hashing

def compress_loop(msg_sch_arr: np.ndarray):
#? Initialize working variables to current hash value:
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4
    f = h5
    g = h6
    h = h7

    for i in range(64):
        a_bin = np.binary_repr(a, 32)
        e_bin = np.binary_repr(e, 32)

        S1 = xor( xor( rrotate(e_bin, 6), rrotate(e_bin, 11)), rrotate(e_bin, 25))
        ch = (e & f) ^ ((~e) & g)
        temp1 = h + np.uint32(int(S1, 2)) + ch + k_const[i] + np.uint32(int(msg_sch_arr[i], 2))

        S0 = xor( xor( rrotate(a_bin, 2), rrotate(a_bin, 13)), rrotate(a_bin, 22))
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = np.uint32(int(S0, 2)) + maj

        h = g
        g = f
        f = e
        e = d + temp1
        d = c
        c = b
        b = a
        a = temp1 + temp2
    
    return [a, b, c, d, e, f, g, h]


#! Produce the final hash value
#* Append together the eight 32-bit h_values 
#* always produces a hash output that is 256 bits long (64 hex chars)

def digest(*h_values: np.uint32):
    final_hash = ""
    for val in h_values:
        final_hash += (np.binary_repr(val, 32))
    return final_hash


# A function containing the entire hashing process
def SHA256_hashing(message: str):

    h0: np.uint32 = 0x6a09e667
    h1: np.uint32 = 0xbb67ae85
    h2: np.uint32 = 0x3c6ef372
    h3: np.uint32 = 0xa54ff53a
    h4: np.uint32 = 0x510e527f
    h5: np.uint32 = 0x9b05688c
    h6: np.uint32 = 0x1f83d9ab
    h7: np.uint32 = 0x5be0cd19

    pad_msg = padding(message)
    chk_msg = chunks_512bits(pad_msg)

    for chunk in chk_msg:
        arr_msg = create_msg_sch_arr(chunk)
        filled_arr_msg = extend_bitwise_op(arr_msg)
        hash_values = compress_loop(filled_arr_msg)

        h0 += hash_values[0]
        h1 += hash_values[1]
        h2 += hash_values[2]
        h3 += hash_values[3]
        h4 += hash_values[4]
        h5 += hash_values[5]
        h6 += hash_values[6]
        h7 += hash_values[7]
    
    hashed_bin_msg = digest(h0, h1, h2, h3, h4, h5, h6, h7)
    hashed_msg = format(int(hashed_bin_msg, base=2), 'x')
    return hashed_msg
