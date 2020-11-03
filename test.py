from feistel import linear_subkey_generation, linear_round_function, Feistel
from feistel import round_function_task_5, round_function_task_7, bit_array_to_hex
from feistel import meet_in_the_middle_attack, vulnerability, linear_cryptoanalysis

import numpy as np

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
print("\nTASK 3 AND 4\n")
u = np.random.randint(2, size=(lu))
k = np.random.randint(2, size=(lu))
feistel = Feistel(32, k, 17, linear_round_function, linear_subkey_generation)
x = feistel.encrypt(u)
a_matrix,b_matrix = vulnerability(32,32,32,17)
key = linear_cryptoanalysis(a_matrix,b_matrix,u,x)
print("u:",bit_array_to_hex(u))
print("k:",bit_array_to_hex(k))
print("x:",bit_array_to_hex(x))
print("k_hat:", bit_array_to_hex(key))

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

print("".join(["-" for _ in range(20)]))
print("\nTASK 8\n")

n_messages = 4
u = np.random.randint(2, size=(n_messages, lu), dtype=int)
k_1 = np.random.randint(2, size=(lu), dtype=int)
k_2 = np.random.randint(2, size=(lu), dtype=int)

first_cipher = Feistel(16, k_1, n, round_function_task_7, linear_subkey_generation)
second_cipher = Feistel(16, k_2, n, round_function_task_7, linear_subkey_generation)

x = []

for i in range(n_messages):
    x_temp = first_cipher.encrypt(u[i])
    x_final = second_cipher.encrypt(x_temp)
    x.append(x_final)

possible_keys = meet_in_the_middle_attack(u, x, first_cipher)
print("Key found with attack: ", [str(k) for k in possible_keys])
print("True key: ", bit_array_to_hex(k_1), bit_array_to_hex(k_2))


