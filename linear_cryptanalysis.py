from feistel import Feistel, linear_round_function, linear_subkey_generation, bit_array_to_hex
from feistel import vulnerability, linear_cryptoanalysis
import numpy as np

a_matrix,b_matrix = vulnerability(32,32,32,17)

# u_hex = "0x80000000"
# x_hex = "0xD80B1A63"

u = np.random.randint(2, size=(32))
k = np.random.randint(2, size=(32))
# u = np.array([int(i == 0) for i in range(32)])
# k = np.array([int(i == 0) for i in range(32)])

feistel = Feistel(32, k, 17, linear_round_function, linear_subkey_generation)
x = feistel.encrypt(u)
#convert hex number in bin number
#create matrix with bits
# u = np.empty([1,32],dtype=int)
# x = np.empty([1,32],dtype=int)

# u_bin = bin(int(u_hex, 16))[2:].zfill(32)
# x_bin = bin(int(x_hex, 16))[2:].zfill(32)

# u[0,:] = [int(d) for d in str(u_bin)]
# x[0,:] = [int(d) for d in str(x_bin)]

key = linear_cryptoanalysis(a_matrix,b_matrix,u,x)
print("u:",bit_array_to_hex(u))
print("k:",bit_array_to_hex(k))
print("x:",bit_array_to_hex(x))
print("k_p:", bit_array_to_hex(key))
