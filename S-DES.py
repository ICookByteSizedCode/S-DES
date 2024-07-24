#Parameters
block_count = 1

# Key generation parameters
kg_P10=(2, 4, 1, 6, 3, 9, 0, 8, 7, 5)
kg_P8=(5, 2, 6, 3, 7, 4, 9, 8)

# Encryption parameters
en_IP=(1, 5, 2, 0, 3, 7, 4, 6)
en_IP_inverse=(3, 0, 2, 4, 6, 1, 7, 5)

# Mapping parameters
mp_EP=(3, 0, 1, 2, 1, 2, 3, 0)

mp_matrix_s0=[
                [1, 0, 3, 2],
                [3, 2, 1, 0],
                [0, 2, 1, 3],
                [3, 1, 3, 2]
            ]

mp_matrix_s1=[
                [0, 1, 2, 3],
                [2, 0, 1, 3],
                [3, 0, 1, 0],
                [2, 1, 0, 3]
            ]

mp_P4=(1, 3, 2, 0)

def create_keystring(key, size):
    return bin(key)[2:].zfill(size)

def permute_key(key, permutation):
    rstring=""
    for i in permutation:
        rstring += key[i]
    return rstring

def left_shift(key, shift):
    return key[shift:]+key[:shift]




def s_des_keygen(key):

    print("_______key generation_______")
    primary_key = create_keystring(key, 10)
    print("converting key into binary: " + primary_key)
    primary_key = permute_key(primary_key, kg_P10)
    print("After initial permutation key is: " + primary_key)
    primary_key = left_shift(primary_key[:5], 1) + left_shift(primary_key[5:], 1)
    print("After applying left circular shift by 1 on two sub parts of key, we get: " + primary_key)
    key1= permute_key(primary_key, kg_P8)
    print("Key1 is: " + key1)

    primary_key=left_shift(primary_key[:5], 2) + left_shift(primary_key[5:], 2)
    print("After applying left circular shift by 2 to find key 2")
    key2 = permute_key(primary_key, kg_P8)
    print("Key2 is: " + key2)
    return key1,key2







def SBox(input_bitstring, s_matrix):

    row=int(input_bitstring[0] + input_bitstring[3], 2)
    column = int(input_bitstring[1:3], 2)

    return bin(s_matrix[row][column])[2:].zfill(2)

def MappingF(input_bitstring, keystring):
    expanded_bitstring = permute_key(input_bitstring, mp_EP)
    bitstring=bin(int(expanded_bitstring, 2)^int(keystring, 2))[2:].zfill(8)
    left_bits=bitstring[:4]
    right_bits=bitstring[4:]
    left_out=SBox(left_bits, mp_matrix_s0)
    right_out=SBox(right_bits, mp_matrix_s1)

    return permute_key(left_out+right_out, mp_P4)

def complex_function(left_bitstring, right_bitstring, keystring):
    left_bit=int(left_bitstring, 2)
    left_out=left_bit^int(MappingF(right_bitstring, keystring), 2)
    return bin(left_out)[2:].zfill(4),right_bitstring



def s_des_encrypt(bitstring, key1, key2, decrypt=False):
    global block_count
    if decrypt:
        print("\n\n Decryption process for block number " + str(block_count) + "_____")
        key2,key1=key1,key2
    else:

        print("\n\n Encryption process for block number " + str(block_count) + "_____")
    print("Initial plaintext string: " + bitstring)
    bitstring = permute_key(bitstring, en_IP)
    print("string after initial permutation: " + bitstring)
    left,right = complex_function(bitstring[:4], bitstring[4:], key1)
    print("String after first round: " + left + right)
    print("Interchanging left bits with right bits: " + right + left)
    left,right = complex_function(right, left, key2)
    print("String after second round: " + left + right)
    x = permute_key(left+right, en_IP_inverse)
    print("String after inverse permutation: " + x)
    block_count+=1
    return x
