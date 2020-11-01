from feistel import linear_subkey_generation, linear_round_function, Feistel
import numpy as np

n = 17
lu = 32
u = np.array([int(i == 0) for i in range(32)])
k = np.array([int(i == 0) for i in range(32)])

print(f"key: {k}")


linear_feistel = Feistel(32, k, n, linear_round_function, linear_subkey_generation)
x = linear_feistel.encrypt(u)
u_hat = linear_feistel.decrypt(x)
print(f"ciphertext: {x}")
print(f"decoded message: {u_hat}")

