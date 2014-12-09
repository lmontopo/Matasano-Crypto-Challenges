#CRYPTO CHALLENGE 1.1
import base64
import binascii

def test(expected, result, set, challenge):
    assert (expected == result), "Set#{0} Challenge#{1} failed. \nIs:     {2}\nShould: {3}".format(set, challenge, result, expected)
    print("Set#{0} Challenge#{1} passed".format(set, challenge))

def hex_to_byte(string):
    return bytes.fromhex(string)

def hex_to_bytearray(string):
    return bytearray(bytes.fromhex(string))

def string_to_bytearray(string):
    return bytearray(string, "ascii")

def bytearray_to_hex(barray):
    return binascii.hexlify(barray)

def base_64(bytes):
    return base64.b64encode(bytes)

# ------------ FIRST CHALLENGE ------------------------ #

input    = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

expected = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
result   = base_64(hex_to_bytearray(input))

test(expected, result, 1, 1);

# ----------- SECOND CHALLENGE ---------------------- #

string_1 = '1c0111001f010100061a024b53535009181c'
string_2 = '686974207468652062756c6c277320657965'
byte_1 = hex_to_bytearray(string_1)
byte_2 = hex_to_bytearray(string_2)

zipped = zip(byte_1, byte_2)
xor = lambda pair : pair[0] ^ pair[1]

expected = b'746865206b696420646f6e277420706c6179'
result   = bytearray_to_hex(bytearray(list(map(xor, zipped))))

test(expected, result, 1, 2)

# ------------ THIRD CHALLENGE ---------------------- #

string = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
barray = hex_to_bytearray(string)

def scoring(barray):
    score = 0 
    for byte in barray:
        if byte in range(65,91) or byte in range(97, 123) or byte == 32:
            score += scoring_table[chr(byte)] 	
    return score

scoring_table = {
  " " : 20,
  "a" : 8, "A" : 8,
  "b" : 1, "B" : 1,
  "c" : 2, "C" : 2,
  "d" : 4, "D" : 4,
  "e" : 12, "E" : 12,
  "f" : 2, "F" : 2,
  "g" : 2, "G" : 2,
  "h" : 6, "H" : 6,
  "i" : 6, "I" : 6,
  "j" : 1, "J" : 1,
  "k" : 1, "K" : 1,
  "l" : 4, "L" : 4,
  "m" : 2, "M" : 2,
  "n" : 6, "N" : 6,
  "o" : 7, "O" : 7,
  "p" : 1, "P" : 1,
  "q" : 1, "Q" : 1,
  "r" : 5, "R" : 5,
  "s" : 6, "S" : 6,
  "t" : 9, "T" : 9,
  "u" : 2, "U" : 2,
  "v" : 1, "V" : 1,
  "w" : 2, "W" : 2,
  "x" : 1, "X" : 1,
  "y" : 1, "Y" : 1,
  "z" : 1, "Z" : 1
}

def topScoring(barray):
    return sorted([[i, bytearray(x ^ i for x in barray)] for i in range(255)], 
        key = lambda pair : scoring(pair[1]), reverse = True)[0]

expected = "Cooking MC's like a pound of bacon"

top = topScoring(barray)
test(expected, top[1].decode("ascii"), 1, 3)

# ------------ FOURTH CHALLENGE ---------------------- #

file = open("4.txt", "r")

count = 0
topScore = 0
scoringLambda = lambda line : topScoring(hex_to_bytearray(line.rstrip()))
best = sorted(map(scoringLambda, file), key = lambda top : scoring(top[1]), reverse = True)[0]

expected = "Now that the party is jumping"
test(expected, best[1].decode("ascii").rstrip(), 1, 4)

# ------------ FIFTH CHALLENGE ---------------------- #

stance = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

barray = string_to_bytearray(stance)
key = string_to_bytearray("ICE");

for i in range(0, len(barray)):
    barray[i] = key[i % 3] ^ barray[i]

expected = b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
test(expected, bytearray_to_hex(barray), 1, 5)

# ------------ SIXTH CHALLENGE ---------------------- #

def hamming(s1, s2):
    assert(len(s1)==len(s2))

    b1 = string_to_bytearray(s1)
    b2 = string_to_bytearray(s2)

    different_bits = 0
    for i in range(len(b1)):
        byte1 = b1[i]
        byte2 = b2[i]

        j = 8
        while j>0:
            different_bits += ((byte1 & 1) ^ (byte2 & 1))
            byte1 = byte1 >> 1
            byte2 = byte2 >> 1
            j -= 1
        
    return different_bits

def normalized_hamming(s1, s2):
    return hamming(s1, s2)/len(s1)

#print(normalized_hamming("HU", "If"))
