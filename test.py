from feistel import linear_subkey_generation, linear_round_function, Feistel
import numpy as np

def bit_array_to_hex(bit_array):

    #defining the hex character
    HEX_CHAR = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"]

    #grouping by 4 the bits
    blocks = np.reshape(np.copy(bit_array), (-1, 4))

    #generating the powers of 2 to be multiplied by the bits
    powers =  np.reshape(2 ** np.arange(4), (1, 4))
    powers = powers[:, ::-1]

    blocks *= powers

    #finding the number from 0 to 15 representing the hex value for the 4 bits
    hex_int = np.sum(blocks, axis = 1, dtype=int)

    return  "0x" + "".join([HEX_CHAR[i] for i in hex_int])

n = 17
lu = 32
u = np.array([int(i == 0) for i in range(32)])
k = np.array([int(i == 0) for i in range(32)])
# u = np.arange(32)+1

# print(f"key: {k}")


linear_feistel = Feistel(32, k, n, linear_round_function, linear_subkey_generation)
x = linear_feistel.encrypt(u)
u_hat = linear_feistel.decrypt(x)
print(f"message: {bit_array_to_hex(u)}")
print(f"key: {bit_array_to_hex(k)}")
print(f"ciphertext: {bit_array_to_hex( x )}")
print(f"decoded message: {bit_array_to_hex( u_hat )}")

count=0
n_checks = 10000
for i in range(n_checks):
    #generating random message
    u = np.random.randint(2, size=(32))

    #generating random key
    k = np.random.randint(2, size=(32))
    linear_feistel.set_key(k)

    #encryption and decryption
    x = linear_feistel.encrypt(u)
    u_hat = linear_feistel.decrypt(x)

    #checking that u and u_hat are the same
    if (np.sum(u-u_hat) == 0):
        count+=1

print(f"key correctly decrypted {count} times out of {n_checks}")
