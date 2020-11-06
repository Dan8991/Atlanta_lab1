from feistel import linear_subkey_generation, linear_round_function, Feistel
from feistel import round_function_task_5, round_function_task_7, bit_array_to_hex
from feistel import meet_in_the_middle_attack, vulnerability, linear_cryptoanalysis
from feistel import get_message_cipher_from_file, explore_close_solutions

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
a_matrix,b_matrix = vulnerability(32,32,32,17, linear_round_function, linear_subkey_generation)
u, x = get_message_cipher_from_file("KPAdataAtlanta/KPApairsAtlanta_linear.hex", 32)
predicted_keys = []
for i in range(u.shape[0]):
    key = linear_cryptoanalysis(a_matrix,b_matrix,u[i],x[i])
    predicted_keys.append(key)

final_key = np.unique(predicted_keys, axis=0)
print(f"key: {bit_array_to_hex(final_key[0])}")
feistel.set_key(final_key[0])
for u_i,x_i in zip(u,x):
    x_p = feistel.encrypt(u_i)

    print(f"u: {bit_array_to_hex(u_i)}, x_hat:{bit_array_to_hex(x_p)}, x:{bit_array_to_hex(x_i)}")

print("".join(["-" for _ in range(20)]))
print("\nTASK 5\n")
n = 5
u = np.array([0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0])
k = np.array([1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1])
cipher_task_5 = Feistel(lu, k, n, round_function_task_5, linear_subkey_generation)
test_cipher(u, k, cipher_task_5)

print("".join(["-" for _ in range(20)]))
print("\nTASK 6\n")

a_matrix,b_matrix = vulnerability(32,32,32,5, linear_round_function, linear_subkey_generation)
feistel = Feistel(32, np.zeros(32), 5, round_function_task_5, linear_subkey_generation)
u, x = get_message_cipher_from_file("KPAdataAtlanta/KPApairsAtlanta_nearly_linear.hex", 32)

predicted_keys = []

for i in range(u.shape[0]):
    key = linear_cryptoanalysis(a_matrix, b_matrix, u[i],x[i])
    predicted_keys.append(key)

keys, counts = np.unique(predicted_keys, return_counts=True, axis = 0)
final_key = None
for key in keys:

    count = 0
    feistel.set_key(key.astype(int))

    for u_i, x_i in zip(u, x):

        x_hat = feistel.encrypt(u_i)

        if np.sum(np.abs(x_hat - x_i)) == 0:
            count += 1

    if count == len(u):
        final_key = key
        break

    final_key = explore_close_solutions(u, x, key, feistel)
    if final_key is not None:
        break

if final_key is not None:
    print(f"key: {bit_array_to_hex(final_key)}")
    feistel.set_key(final_key.astype(int))
    for u_i,x_i in zip(u,x):
        x_p = feistel.encrypt(u_i)
        print(f"u: {bit_array_to_hex(u_i)}, x_hat:{bit_array_to_hex(x_p)}, x:{bit_array_to_hex(x_i)}")
else:
    print("Found no suitable key")


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

first_cipher = Feistel(16, np.zeros(16), n, round_function_task_7, linear_subkey_generation)
second_cipher = Feistel(16, np.zeros(16), n, round_function_task_7, linear_subkey_generation)

print("This might take some time depending on how many keys you are testing(2 min max usually)")
u, x = get_message_cipher_from_file("KPAdataAtlanta/KPApairsAtlanta_non_linear.hex", 16)
possible_keys = meet_in_the_middle_attack(u, x, first_cipher, 15)
correct_key = possible_keys

if len(correct_key) > 0:
    print("Keys found with attack: ", str(correct_key[0]))
    first_cipher.set_key(correct_key[0].k1)
    second_cipher.set_key(correct_key[0].k2)
    correct = 0
    for u_i, x_i in zip(u, x):
        x_hat = second_cipher.encrypt(first_cipher.encrypt(u_i))
        print(f"u: {bit_array_to_hex(u_i)}, x_hat: {bit_array_to_hex(x_hat)}, x: {bit_array_to_hex(x_i)}")
else:
    print("No suitable key found")

