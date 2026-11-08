"""Share of random hex values with Shannon entropy below a floor, counted exactly.

Usage: python3 eval/hex_entropy_floor.py <digits> <floor>
(for example: 32 3.0, which prints 1 in 9,468). Every string of <digits> hex digits
is counted by its multiset of digit counts, so the result is exact, not sampled.
"""
import math, sys
from math import factorial

def parts(n, k, m=None):
    """Partitions of n into at most k parts (each part <= m), non-increasing."""
    if m is None:
        m = n
    if n == 0:
        yield ()
        return
    if k == 0:
        return
    for first in range(min(n, m), 0, -1):
        for rest in parts(n - first, k - 1, first):
            yield (first,) + rest

def below(n, floor):
    total = 0
    for p in parts(n, 16):
        h = -sum(c / n * math.log2(c / n) for c in p)
        if h < floor:
            ways = factorial(n)
            for c in p:
                ways //= factorial(c)
            # assign the multiset of counts to distinct digits
            from collections import Counter
            used = len(p)
            assign = factorial(16) // factorial(16 - used)
            for mult in Counter(p).values():
                assign //= factorial(mult)
            total += ways * assign
    return total

n, floor = int(sys.argv[1]), float(sys.argv[2])
b = below(n, floor)
print(f"{b} of 16^{n}: 1 in {16**n / b:,.0f}")
