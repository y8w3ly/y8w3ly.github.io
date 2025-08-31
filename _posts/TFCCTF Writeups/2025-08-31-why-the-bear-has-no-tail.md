---
layout: post
title: WHY THE BEAR HAS NO TAIL
date: 2025-08-31 00:00:00 +0000
categories: [misc,crypto]
tags: [mersenne]
description: Writeup of cry/wtbnt that I solved in TFCCTF
author_profile: true
toc: true
toc_sticky: true
excerpt: "Break python's PRNG with missing bits"
---


last weekend i played tfctf 2025 w my team @Trojeun (big thx to [TheFewChosen](https://ctftime.org/team/140885) for hosting) i somehow managed to solve this crypto chall (16th solve )


## Challenge Overview

- **CTF**: TFCCTF 2025
- **Challenge**: WHY THE BEAR HAS NO TAILS
- **Category**: Crypto
- **Description**: It's 6am and I'm about to fall asleep cause we didn't have enough baby challenges apparently. Anyways, you see why the bear has no tail?
- **Connection info** : `ncat the-bear-7377a1df9ab40606.challs.tfcctf.com 1337 --ssl`
- **Challenge file** : [chall.py](/assets/files/tcfctf/chall.py)

## TL;DR
the chall leaks mt state from python random cuz of how `random.choices(range(2**26))` works  
each sample → top 26 bits of tempered mt output (like getrandbits(26))  
~768 samples enough to recover all state w z3  
once u got state u regen the same xor key → flag pop out ez

## Initial Analysis
we got a py service w 3 funcs:
+ `get_sample()` :
```python
def get_sample(self):
        self.index += 1
        if self.index > self.k:
            print("Reached end of buffer")
        else:
            print("uhhh here is something but idk what u finna do with it: ", random.choices(range(self.n), k=1)[0])
```
Returns one integer in `[0, 2**26]` via `random.choices(range(self.n), k=1)[0]`.

Since `n = 2**26`, this is equivalent to calling `getrandbits(26)`, i.e. the top 26 bits of a tempered MT output.

+ `get_flag()` :
```python
def get_flag(self):
        idxs = [i for i in range(256)]  
        key = random.choices(idxs, k=len(FLAG))  
        omlet = [ord(FLAG[i]) ^ key[i] for i in range(len(FLAG))]  
        print("uhh ig I can give you this if you really want it... chat?", omlet)
```
Builds a key with `random.choices(range(256), k=len(FLAG))` and XORs it with the flag. Each key byte is just `getrandbits(8)` from the PRNG.

+ So essentially
    - samples leak 26 msbs
    - flag enc eats len(flag) mt outputs

## Task Analysis

+ What we get
    - 2000 calls to `get_sample()` → 26 bits each
    - encrypted flag array

+ What we need
    - recover mt state from partial outs
    - recreate same key seq
    - xor and profit

+ constraints
    - mt state = 624×32 = 19968 bits
    - sample = 26 bits
    - need ~768 samples → we got 2000 so chill

So What I did first is to search about how to recover 32bits prng state with missing bits, and after a lot of dorking I found this [stackExchange](https://crypto.stackexchange.com/questions/92129/how-can-i-recover-mersenne-twister-when-only-the-part-of-the-bits) in which someone asked the same question as me and someone answered : 
+ Use this [repo](https://github.com/icemonster/symbolic_mersenne_cracker). It allows you to tell what parts you are missing from the usual 32-bit parts in order to submit non-consecutive ints.
So I accessed it and in the `main.py` we can find a function named `test` where we can understand how it works : 
```python
def test():
    '''
        This test tries to clone Python random's internal state, given partial output from getrandbits
    '''

    r1 = Random()
    ut = Untwister()
    for _ in range(1337):
        random_num = r1.getrandbits(16)
        #Just send stuff like "?11????0011?0110??01110????01???"
            #Where ? represents unknown bits
        ut.submit(bin(random_num)[2:] + '?'*16)

    r2 = ut.get_random()
    for _ in range(624):
        assert r1.getrandbits(32) == r2.getrandbits(32)

    logger.debug('Test passed!')
```

So we understood that we need to submit each time the 26bits that we recieve from the server then `6*'?'` to complete 32bits.

## The Attack

### recovering known bits
+ script talks w server oracle
+ it gets 26 bits over n over
+ we store like 2000 samples of those

### aligning With 32bit
+ once 26 bits are known, there are still 6 unknown bits left.
+ to ensure the guess is the correct full length (32bits), the script sends: `known_26_bits + 6 * '?'`
+ this acts as a checkpoint: the server validates the prefix (26 correct bits), while the last 6 are placeholders.

### resetting for brute force
+ then we submit:`32*'?'`
+ you should ask why? → (honestly it came by chance)starting clean w all wildcards makes oracle happy
+ looks like we “lost” 26 bits but nah they already confirmed earlier
+ this reset avoids mismatch n lets us brute force clean

### recovering remaining bits n getting state
+ now we brute those 6 unknown bits step by step
+ once they’re done we get full 32bits out of each sample
+ after enough of those → boom mt state rebuilt

### Ggetting key then flaglag
+ with `.get_random()` we regen state
+ then just call `rnd.choices(list(range(256)),k=95)` to rebuild key
+ xor enc bytes with key → flag pops out

## Conclusion

```python
from pwn import remote
from z3 import *
from random import Random
from itertools import count
import ast


#All helper functions are in the repo

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


ut = Untwister()
for i in range(2 * flagLen):
    ut.submit("?"*32)

for s in samples:
    ut.submit(sample_to_guess(s))
    ut.submit("?"*32)


rnd = ut.get_random()
key = rnd.choices(list(range(256)), k=flagLen)

flag = ''.join(chr(enc[i] ^ key[i]) for i in range(flagLen))
print(flag)
```

And here is the flag : `TFCCTF{nowu4r5987489579_ready_to_b3AAAt58435945_online_casions????!847857w89478954w93894829384}`

you can find the full solve script here[sol.py](/assets/files/tfcctf/sol.py)

