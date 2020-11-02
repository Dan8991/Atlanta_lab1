from feistel import linear_subkey_generation, linear_round_function, Feistel
from feistel import round_function_task_5, round_function_task_7

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

def test_cipher(u, k, cipher, perform_check=False):

    x = cipher.encrypt(u)
    u_hat = cipher.decrypt(x)

    print(f"message: {bit_array_to_hex(u)}")
    print(f"key: {bit_array_to_hex(k)}")
    print(f"ciphertext: {bit_array_to_hex( x )}")
    print(f"decoded message: {bit_array_to_hex( u_hat )}")

    if perform_check:

        count=0
        n_checks = 10000

        for _ in range(n_checks):
            #generating random message
            u = np.random.randint(2, size=(lu))

            #generating random key
            k = np.random.randint(2, size=(lu))
            linear_feistel.set_key(k)

            #encryption and decryption
            x = linear_feistel.encrypt(u)
            u_hat = linear_feistel.decrypt(x)

            #checking that u and u_hat are the same
            if (np.sum(u-u_hat) == 0):
                count+=1

        print(f"key correctly decrypted {count} times out of {n_checks}")


print("\nTASK 1 AND 2\n")
n = 17
lu = 32
u = np.array([int(i == 0) for i in range(lu)])
k = np.array([int(i == 0) for i in range(lu)])
linear_feistel = Feistel(lu, k, n, linear_round_function, linear_subkey_generation)
test_cipher(u, k, linear_feistel)


print("".join(["-" for _ in range(20)]))
print("\nTASK 5\n")
n = 5
u = np.array([0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0])
k = np.array([1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1])
cipher_task_5 = Feistel(lu, k, n, round_function_task_5, linear_subkey_generation)
test_cipher(u, k, cipher_task_5)


print("".join(["-" for _ in range(20)]))
print("\nTASK 7\n")
n = 13
lu = 16
u = np.array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
k = np.array([0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0])
cipher_task_7 = Feistel(16, k, n, round_function_task_7, linear_subkey_generation)
test_cipher(u, k, cipher_task_7)
