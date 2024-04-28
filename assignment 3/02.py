def gf_add(a, b):
    return a ^ b

def gf_multiply(a, b):
    p = 0
    while b:
        if b & 1:
            p ^= a
        a <<= 1

        # if the 9th bit get set, we XOR to modulo with 0b100011011
        if a & 0b100000000:
            a ^= 0b100011011
        b >>= 1
    return p & 0xff

def gf_divide(a, b):
    if b == 0:
        raise ZeroDivisionError()
    if a == 0:
        return 0
    tmp = [0, 0, 0, 0, 0, 0, 0, 0, 0]
    for i in range(1, 9):
        if (b << (i - 1)) & 0x100:
            tmp[9 - i] = 1
    for i in range(8):
        if ((a << i) & 0x100) and tmp[0] == 1:
            for j in range(9):
                a ^= (tmp[j] << (8 - j))
        tmp = [tmp[-1]] + tmp[:-1]
    return a

def main():
    a = input("Enter the first bit string: ")
    b = input("Enter the second bit string: ")
    operation = input("Enter the operation (add, multiply, divide): ")

    try:
        a = int(a, 2)
        b = int(b, 2)
    except:
        raise ValueError("Invalid bit string")

    if operation == 'add':
        result = gf_add(a, b)
    if operation == 'subtract':
        result = gf_add(a, b)
    elif operation == 'multiply':
        result = gf_multiply(a, b)
    elif operation == 'divide':
        result = gf_divide(a, b)
    else:
        raise ValueError("Invalid operation")

    print("The result is: ", bin(result)[2:].zfill(8))

if __name__ == "__main__":
    main()