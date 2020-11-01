import numpy as np

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

