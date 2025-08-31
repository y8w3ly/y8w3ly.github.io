import random
from secret_stuff import FLAG

class Challenge():
    # this function initializes the challenge parameters (max number range, buffer size, and index counter)
    def init(self):
        self.n = 2**26      # range of numbers to sample from
        self.k = 2000       # maximum number of samples allowed
        self.index = 0      # keeps track of how many samples have been given

    # this function gives a random sample (a random number in range [0, n)), 
    # but only up to k times, otherwise prints a message when the limit is reached
    def get_sample(self):
        self.index += 1
        if self.index > self.k:
            print("Reached end of buffer")
        else:
            print("uhhh here is something but idk what u finna do with it: ", random.choices(range(self.n), k=1)[0])

    # this function tries to "give the flag" but actually XORs each character of the FLAG 
    # with a random key, producing an encrypted version of the flag instead of the real one
    def get_flag(self):
        idxs = [i for i in range(256)]  # possible key values (0–255)
        key = random.choices(idxs, k=len(FLAG))  # random key of same length as FLAG
        omlet = [ord(FLAG[i]) ^ key[i] for i in range(len(FLAG))]  # XOR each character with key
        print("uhh ig I can give you this if you really want it... chat?", omlet)

    # this function runs an interactive loop where the user chooses between:
    # 1) getting a random sample, or 2) getting an encrypted version of the flag
    def loop(self):
        while True:
            print("what you finna do, huh?")
            print("1. guava")
            print("2. muava")
            choice = input("Enter your choice: ")
            if choice == "1":
                self.get_sample()
            elif choice == "2":
                self.get_flag()
            else:
                print("Invalid choice")


if __name__ == "__main__":
    c = Challenge()
    c.loop()
