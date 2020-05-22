from hashlib import sha256
import os
from time import sleep
from math import log2
from threading import Thread, Lock
from datetime import datetime
from math import ceil
import pickle

order = 'big' # big endian
size = 32


def str_to_bytes(string):
    return string.encode('utf-8')

sha15_len = 15
sha16_len = 16
sha17_len = 17
sha18_len = 18
sha19_len = 19
sha20_len = 20

hexdigest_base = 16
stop_threads = False
byte_size = 8
int_to_get_first_bits = {
    0: 255,
    1: 128,
    2: 192,
    3: 224,
    4: 240,
    5: 248,
    6: 252,
    7: 254
}


def shaXX(data, x):
    bytes_amount = ceil(x / byte_size)
    sha256_digest = sha256(data).digest()[:bytes_amount]
    result = b''
    for i in range(bytes_amount - 1):
        result += sha256_digest[i].to_bytes(1, 'big')
    last_byte = sha256_digest[bytes_amount - 1]
    last_byte &= int_to_get_first_bits[x % byte_size]
    result += last_byte.to_bytes(1, 'big')
    return result


def sha15(data):
    return shaXX(data, 15)


def sha16(data):
    return shaXX(data, 16)


def sha17(data):
    return shaXX(data, 17)


def sha18(data):
    return shaXX(data, 18)


def sha19(data):
    return shaXX(data, 19)


def sha20(data):
    return shaXX(data, 20)


def P(x, k):
    zero = 0
    add_part = b''
    for _ in range(ceil(k / byte_size)):
        add_part += zero.to_bytes(1, 'big')
    return x + add_part


def check_if_first_q_bits_are_zero(data, q):
    bytes_amount = ceil(q / 8)
    for i in range(bytes_amount - 1):
        if data[i] != 0:
            return False
    last_byte = data[bytes_amount - 1]
    if last_byte & int_to_get_first_bits[q % byte_size] != 0:
        return False
    return True



def generate_pollard_collision(S, hash_function, q, y0, results, thread_id, k):
    y_i = P(hash_function(y0), k)
    i = 1
    while(True):
        global stop_threads
        if stop_threads:
            break
        y_i = P(hash_function(y_i), k)
        i += 1
        sleep(0.0001)
        if check_if_first_q_bits_are_zero(y_i, q):
            S_lock = Lock()
            with S_lock:
                j_id = S.get(y_i)
                if j_id is not None:
                    stop_threads = True
                    results.append((i, y0, j_id[1] == thread_id))
                    results.append(j_id[0])
                else:
                    S[y_i] = (i, thread_id)


def found(y0, z0, i, j, hash_function, k):
    if i >= j:
        d = i - j
        y = P(hash_function(y0), k)
        for _ in range(d-1):
            y = P(hash_function(y), k)
        z = z0
    else:
        d = j - i
        z = P(hash_function(z0), k)
        for _ in range(d-1):
            z = P(hash_function(z), k)
        y = y0
    while P(hash_function(y), k) != P(hash_function(z), k):
        y = P(hash_function(y), k)
        z = P(hash_function(z), k)
    return (y, z)


def count_y_z(hash_function, results, y0, z0, k):
    i, j = results[0][0], results[1]
    if results[0][2]:
        if results[0][1] == y0:
            collision = found(y0, y0, i, j, hash_function, k)
        else:
            collision = found(z0, z0, i, j, hash_function, k)
    elif results[0][1] == y0:
        collision = found(y0, z0, i, j, hash_function, k)
    else:
        collision = found(z0, y0, i, j, hash_function, k)
    return (collision[0], collision[1])


def pollard_attack(hash_function, amount, k):
    m = 2
    q = int(len(hash_function(str_to_bytes('test'))) / 2 - log2(m))
    collisions_set = set()
    collisions = []
    amount_stored_hashs = 0
    while len(collisions) != amount:
        S = {}
        results = []

        y0 = hash_function(os.urandom(size))
        z0 = hash_function(os.urandom(size))

        thread_1 = Thread(target=generate_pollard_collision, args=[S, hash_function, q, y0, results, 1, k])
        thread_2 = Thread(target=generate_pollard_collision, args=[S, hash_function, q, z0, results, 2, k])
        thread_1.start()
        thread_2.start()
        thread_1.join()
        thread_2.join()

        global stop_threads
        stop_threads = False
        amount_stored_hashs += len(S)

        y, z = count_y_z(hash_function, results, y0, z0, k)
        if y not in collisions_set and z not in collisions_set:
            collisions_set.add(y)
            collisions_set.add(z)
            collisions.append((y, z))
            print(len(collisions))

    return (collisions, amount_stored_hashs)


def measuring_and_write_to_file(attack_function, hash_function, collisions_amount, k, filename):
    start_time = datetime.now()
    attack = attack_function(hash_function, collisions_amount, k)
    collisions = attack[0]
    amount_stored_hashs = attack[1]
    execution_time = datetime.now() - start_time
    with open(filename, 'w') as file:
        for i, col in enumerate(collisions, start=1):
            y, z = col[0].hex(), col[1].hex()
            # print(i, y, z)
            file.write('i = %s\ny = %s\nz = %s\n\n' % (i, y, z))
    return (execution_time.total_seconds(), amount_stored_hashs)

if __name__ == "__main__":
    results_pollard_sha15 = measuring_and_write_to_file(pollard_attack, sha15, 100, 5, 'pollard_collisions/sha15.txt')
    results_pollard_sha16 = measuring_and_write_to_file(pollard_attack, sha16, 100, 5, 'pollard_collisions/sha16.txt')
    results_pollard_sha17 = measuring_and_write_to_file(pollard_attack, sha17, 100, 5, 'pollard_collisions/sha17.txt')
    results_pollard_sha18 = measuring_and_write_to_file(pollard_attack, sha18, 100, 5, 'pollard_collisions/sha18.txt')
    results_pollard_sha19 = measuring_and_write_to_file(pollard_attack, sha19, 100, 5, 'pollard_collisions/sha19.txt')
    results_pollard_sha20 = measuring_and_write_to_file(pollard_attack, sha20, 100, 5, 'pollard_collisions/sha20.txt')

    with open('pollard_collisions/results_sha15.pickle', 'wb') as file:
        pickle.dump(results_pollard_sha15, file)

    with open('pollard_collisions/results_sha16.pickle', 'wb') as file:
        pickle.dump(results_pollard_sha16, file)

    with open('pollard_collisions/results_sha17.pickle', 'wb') as file:
        pickle.dump(results_pollard_sha17, file)

    with open('pollard_collisions/results_sha18.pickle', 'wb') as file:
        pickle.dump(results_pollard_sha18, file)

    with open('pollard_collisions/results_sha19.pickle', 'wb') as file:
        pickle.dump(results_pollard_sha19, file)
    
    with open('pollard_collisions/results_sha20.pickle', 'wb') as file:
        pickle.dump(results_pollard_sha20, file)
 

