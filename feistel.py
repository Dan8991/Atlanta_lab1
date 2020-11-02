import numpy as np
from functools import reduce

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


'''
k = key
n = number of rounds
l = message length
'''
def linear_subkey_generation(k, n):

    lk = k.shape[0]
    #the +1 and -1 are not needed here since the indexes start from 0 and not from 1
    subkeys = np.fromfunction(lambda i, j: k[(5 * (i + 1) + j) % lk], (n, lk), dtype=int ) 

    return subkeys

def linear_round_function(y_i, k_i):

    l = y_i.shape[0]

    w_i = np.zeros(l)

    '''
    y_i[j] remains the same since also the indexes in y_i start from 0
    for k_i we would have the index [4j - 3] = [1, 5, 9, ...] for j = [1, 2, ...]
    here the arrays start from 0 so we want to have [0, 4, 8, ...] i.e. 4j
    '''
    w_i[:l//2] = y_i[:l//2] + k_i[::4]


    '''
    in the instructions we have j = [l/2 + 1, l/2 + 2, ...] so here we need j + 1
    furthermore since the indexes of k_i start from 0 we need to place a -1 at the
    end of the indexes
    '''
    w_i[l//2:] = y_i[l//2:] + k_i[3::4]

    #the %2 is needed since we are working with binary numbers
    return w_i % 2

def round_function_task_5(y_i, k_i):
    l = y_i.shape[0]

    w_i = np.copy(y_i)

    '''
    y_i[j] remains the same since also the indexes in y_i start from 0
    for k_i we would have the index [4j - 3] = [1, 5, 9, ...] for j = [1, 2, ...]
    here the arrays start from 0 so we want to have [0, 4, 8, ...] i.e. 4j
    for y_i we would have varius index:
    [2j-1] = [1,3,5,7,...] for j=[1,2,...] here the array start from 0 so 
    we want to have [0,2,4,6,...]
    [2j] = [2,4,6,8,...] --> [1,2,5,7,..]
    [4j-2] = [2,6,10,14,18,...] --> [1,5,9,13,...]
    
    '''
    w_i[:l // 2] += k_i[::4] * ( y_i[::2] | k_i[:l:2] | k_i[1:(l+1):2] | k_i[1::4])

    '''
    in the instructions we have j = [l/2 + 1, l/2 + 2, ...] so here we need j + 1
    furthermore since the indexes of k_i start from 0 we need to place a -1 at the
    end of the indexes
    [4j-2l] = [4,8,12,...] --> [3,7,11,...]
    [4j-2l-1] = [3,7,11,...] --> [2,6,10,...]
    [2j-1] = [9,11,13,...] --> [8,10,12,...]
    [2j] = [10,12,14,...] --> [9,11,13,...]
    [2j-l] = [2,4,6,...] --> [1,3,5,...]
    
    '''
    w_i[l // 2:] += k_i[3::4] * (k_i[2::4] | k_i[l::2] | k_i[(l+1)::2] | y_i[1::2])

    # the %2 is needed since we are working with binary numbers
    return w_i % 2


def round_function_task_7(y_i, k_i):
    l = y_i.shape[0]

    w_i = np.zeros(l, dtype = int)

    '''
    y_i[j] remains the same since also the indexes in y_i start from 0
    for k_i we would have the index [4j - 3] = [1, 5, 9, ...] for j = [1, 2, ...]
    here the arrays start from 0 so we want to have [0, 4, 8, ...] i.e. 4j
    for y_i we would have varius index:
    [2j-1] = [1,3,5,7,...] for j=[1,2,...] here the array start from 0 so 
    we want to have [0,2,4,6,...]
    [2j] = [2,4,6,8,...] --> [1,2,5,7,..]
    [4j] = [4,8,12,...] --> [3,7,11,...]

    '''

    w_i[:l // 2] = (y_i[:l // 2] & k_i[:l:2]) | (y_i[::2] & k_i[1:(l+1):2]) | k_i[3::4]

    '''
    in the instructions we have j = [l/2 + 1, l/2 + 2, ...] so here we need j + 1
    furthermore since the indexes of k_i start from 0 we need to place a -1 at the
    end of the indexes
    [4j-2l-1] = [3,7,11,...] --> [2,6,10,...]
    [2j] = [10,12,14,...] --> [9,11,13,...]
    [2j-l] = [2,4,6,...] --> [1,3,5,...]

    '''

    w_i[l // 2:] = (y_i[l // 2:] & k_i[l::2]) | (k_i[2::4] & k_i[(l+1)::2]) | y_i[1::2]

    # the %2 is needed since we are working with binary numbers
    return w_i % 2



class Feistel():

    '''
    lu = message length lu = lx = 2l 2l 
    k = key
    n = number of rounds
    round_function = round function
    subkey_generation = subkey generation function
    '''

    def __init__(self, lu, key, n, round_function, subkey_generation):

        self.lu = lu
        self.key = key
        self.n = n
        self.round_function = round_function
        self.subkey_generation = subkey_generation
        self.subkeys = subkey_generation(key, n)

    def set_key(self, key):

        self.key = key
        self.subkeys = self.subkey_generation(self.key, self.n)

    #if you pass the subkeys in correct order you get the encryption function
    #in reverse order you get decryption
    def perform_feistel(self, u, subkeys):

        l = u.shape[0] // 2
        #Taking y, v swapped since the swap at the beginning of the cycle will swap them back
        v = u[:l]
        y = u[l:]

        for i in range(self.n):

            #swapping y and z
            z = y
            y = v

            w_i = self.round_function(y, subkeys[i])
            v = (z + w_i) % 2

        return np.concatenate([y, v])

    def encrypt(self, u):
        return self.perform_feistel(u, self.subkeys)

    def decrypt(self, x):
        return self.perform_feistel(x, self.subkeys[::-1,:])

class key_couples():

    def __init__(self, k1, k2):
        self.k1 = k1
        self.k2 = k2
        self.hex_k1 = bit_array_to_hex(k1)
        self.hex_k2 = bit_array_to_hex(k2)

    def __hash__(self):
        key_tot = np.concatenate([self.k1, self.k2])
        powers = 2**np.arange(len(key_tot))
        return int(np.dot(key_tot, powers))

    def __eq__(self, other):
        return self.__hash__() == other.__hash__() 

    def __str__(self):
        return self.hex_k1 + " " + self.hex_k2

def meet_in_the_middle_attack(u, x, feistel, power=15):

    lk = u.shape[1]
    n_guesses = int(2**power)
    #randomly sampling n_guesses keys for the first cipher and n_guesses keys for the second cipher
    k_prime = np.random.randint(2, size=(n_guesses, lk), dtype=int)
    k_second = np.random.randint(2, size=(n_guesses, lk), dtype=int)

    x_prime = []
    x_second = []
    #finding the intermediate ciphers for each of the keys
    for i in range(n_guesses):

        feistel.set_key(k_prime[i])
        x_prime.append((bit_array_to_hex(feistel.encrypt(u[0])), k_prime[i]))

        feistel.set_key(k_second[i])
        x_second.append((bit_array_to_hex(feistel.decrypt(x[0])), k_second[i]))

    #sorting the keys
    x_prime.sort(key=lambda x: x[0])
    x_second.sort(key=lambda x: x[0])

    i = 0
    j = 0
    correct_couples = []

    #searching for matching intermediate keys
    while i < len(x_prime) and j < len(x_second):
        if x_prime[i][0] < x_second[j][0]:
            i += 1
        elif x_prime[i][0] > x_second[j][0]:
            j += 1
        else:
            correct_couples.append(key_couples(x_prime[i][1], x_second[j][1]))
            i+=1
            j+=1

    #removing duplicates
    final_keys = list(set(correct_couples))

    #for all the other u_i, x_i couples see if the keys found before actually work
    for u_i, x_i in zip(u[1:], x[1:]):

        temp_keys = []

        for keys in final_keys:
            feistel.set_key(keys.k1)
            x_prime = bit_array_to_hex(feistel.encrypt(u_i))

            feistel.set_key(keys.k2)
            x_second = bit_array_to_hex(feistel.decrypt(x_i))

            if x_prime == x_second:
                temp_keys.append(keys)

        final_keys = temp_keys



    return final_keys




    


