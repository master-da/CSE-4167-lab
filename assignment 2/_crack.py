import itertools

def decrypt(c, pad, sz):
    m = []
    c = [0] + c
    for i in range(sz):
        m.append(c[i+1] ^ ( (pad[i] ^ c[i]) % 256 ))
    return m

def crack():
    
    acceptable_letters = [33, 39, 40, 41, 44, 45, 46, 63, 65, 66, 67, 68, 69, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122]
    sz = 60
    english_words = []
    
    with open('words', 'r') as f:
        strToHexList = lambda s: [ord(c) for c in s]
        words = f.readlines()
        english_words = [strToHexList(word.strip()) for word in words if word.strip().isalpha()]
    
    
    cipherlist = []
    with open('ciphertext.txt', 'r') as f:
        words = f.readlines()
        for word in words:
            word = word.strip().split(',')
            cipherlist.append([int(w) for w in word])

    for st in itertools.product(acceptable_letters, repeat=4):
        pad = (list(st) + [0] * 60)[:sz]
        for c in cipherlist:
            m = decrypt(c, pad, sz)
            acceptable = True
            for char in m: 
                if char not in acceptable_letters: 
                    acceptable = False
                    break
            if acceptable:
                print(''.join([chr(c) for c in m]))
                
        else:
            continue
        