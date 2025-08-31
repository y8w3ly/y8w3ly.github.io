from pwn import remote
from z3 import *
from random import Random
from itertools import count
from time import time
import logging
import ast

logging.basicConfig(format='STT> %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

SYMBOLIC_COUNTER = count()

class Untwister:
    def __init__(self):
        name = next(SYMBOLIC_COUNTER)
        self.MT = [BitVec(f'MT_{i}_{name}', 32) for i in range(624)]
        self.index = 0
        self.solver = Solver()

    def symbolic_untamper(self, solver, y):
        name = next(SYMBOLIC_COUNTER)

        y1 = BitVec(f'y1_{name}', 32)
        y2 = BitVec(f'y2_{name}' , 32)
        y3 = BitVec(f'y3_{name}', 32)
        y4 = BitVec(f'y4_{name}', 32)

        equations = [
            y2 == y1 ^ (LShR(y1, 11)),
            y3 == y2 ^ ((y2 << 7) & 0x9D2C5680),
            y4 == y3 ^ ((y3 << 15) & 0xEFC60000),
            y == y4 ^ (LShR(y4, 18))
        ]

        solver.add(equations)
        return y1

    def symbolic_twist(self, MT, n=624, upper_mask=0x80000000, lower_mask=0x7FFFFFFF, a=0x9908B0DF, m=397):
        MT = [i for i in MT]
        for i in range(n):
            x = (MT[i] & upper_mask) + (MT[(i+1) % n] & lower_mask)
            xA = LShR(x, 1)
            xB = If(x & 1 == 0, xA, xA ^ a)
            MT[i] = MT[(i + m) % n] ^ xB
        return MT

    def get_symbolic(self, guess):
        name = next(SYMBOLIC_COUNTER)
        ERROR = 'Must pass a string like "?1100???1001000??0?100?10??10010" where ? represents an unknown bit'

        assert type(guess) == str, ERROR
        assert all(map(lambda x: x in '01?', guess)), ERROR
        assert len(guess) <= 32, "One 32-bit number at a time please"
        guess = guess.zfill(32)

        self.symbolic_guess = BitVec(f'symbolic_guess_{name}', 32)
        guess = guess[::-1]

        for i, bit in enumerate(guess):
            if bit != '?':
                self.solver.add(Extract(i, i, self.symbolic_guess) == bit)

        return self.symbolic_guess

    def submit(self, guess):
        if self.index >= 624:
            name = next(SYMBOLIC_COUNTER)
            next_mt = self.symbolic_twist(self.MT)
            self.MT = [BitVec(f'MT_{i}_{name}', 32) for i in range(624)]
            for i in range(624):
                self.solver.add(self.MT[i] == next_mt[i])
            self.index = 0

        symbolic_guess = self.get_symbolic(guess)
        symbolic_guess = self.symbolic_untamper(self.solver, symbolic_guess)
        self.solver.add(self.MT[self.index] == symbolic_guess)
        self.index += 1

    def get_random(self):
        logger.debug('Solving...')
        start = time()
        self.solver.check()
        model = self.solver.model()
        end = time()
        logger.debug(f'Solved! (in {round(end-start,3)}s)')

        state = list(map(lambda x: model[x].as_long(), self.MT))
        result_state = (3, tuple(state+[self.index]), None)
        r = Random()
        r.setstate(result_state)
        return r

def sample_to_guess(s):
    msb26 = format(s, '026b')
    return msb26 + '?'*6

r = remote("the-bear-7377a1df9ab40606.challs.tfcctf.com", 1337, ssl=True)

r.sendlineafter(b"Enter your choice: ", b"2")
r.recvuntil(b"... chat? ")
enc = ast.literal_eval(r.recvline().decode())
flagLen = len(enc)


samples = []

for i in range(2000):
    r.sendlineafter(b"Enter your choice: ", b"1")
    r.recvuntil(b"do with it: ")
    samples.append(int(r.recvline().decode()))
    print(samples)
    
ut = Untwister()

for i in range(2 * flagLen):
    ut.submit("?"*32)
    
for i, s in enumerate(samples):
        guess = sample_to_guess(s)
        ut.submit(guess)
        ut.submit("?"*32)

r.sendlineafter(b"Enter your choice: ", b"2")
r.recvuntil(b"... chat? ")
enc = ast.literal_eval(r.recvline().decode())
flagLen = len(enc)

rnd = ut.get_random()
key = rnd.choices(list(range(256)),k=95)

flag = ''.join(chr(enc[i] ^ key[i]) for i in range(flagLen))
print(flag)
