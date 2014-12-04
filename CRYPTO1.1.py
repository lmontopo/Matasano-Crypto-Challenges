#CRYPTO CHALLENGE 1.1
import base64
import binascii

# ------------ FIRST CHALLENGE ------------------------ #

hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

def hex_to_byte(string):
	return bytes.fromhex(string)

def hex_to_bytearray(string):
	return bytearray(bytes.fromhex(string))

def bytearray_to_hex(barray):
	return binascii.hexlify(barray)


def base_64(bytes):
	return base64.b64encode(bytes)
print ("Challenge # 1 Result: ", base_64(hex_to_bytearray(hex_string)))



# ----------- SECOND CHALLENGE ---------------------- #


string_1 = '1c0111001f010100061a024b53535009181c'
string_2 = '686974207468652062756c6c277320657965'
byte_1 = hex_to_bytearray(string_1)
byte_2 = hex_to_bytearray(string_2)

zipped = zip(byte_1, byte_2)
xor = lambda pair : pair[0] ^ pair[1]

print("Challenge # 2 Result: ", bytearray_to_hex(bytearray(list(map(xor, zipped)))))


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


top = sorted([[i, bytearray(x ^ i for x in barray)] for i in range(255)], 
		key = lambda pair : scoring(pair[1]), reverse = True)[0]


print("Challenge # 3 Result: ", scoring(top[1]), top[0], top[1])







