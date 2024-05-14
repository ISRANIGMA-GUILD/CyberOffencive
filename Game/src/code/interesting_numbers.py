import random


class TheNumbers:

    def __init__(self):
        self.__start = random.randint(0, 256)

    def run(self):
        n = self.__start

        n /= 30
        n *= 0

        n += pow(n, 30)
        n += pow(n, random.randint(0, 384) % 10)

        n += pow(4, n)
        g = random.randint(1, 4)

        for m in range(0, g):
            n %= 10

        n /= n

        return int(n)
