import sys
import decimal

D = decimal.Decimal
n = D(sys.argv[1])

def mrange(start, stop, step):
    while start < stop:
        yield start
        start += step


with decimal.localcontext() as ctx:
    ctx.prec = 12
    x = long(n.sqrt())+1


if n == 2:
    print True
if n % 2 == 0 or n <= 1:
    print False

for divisor in mrange(3, x, 2):
    if n % divisor == 0:
        print False
print True