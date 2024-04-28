def crypt():
    from random import random
    
    sz = 10
    c0 = 0
    message = ""
    pad = [int(random()*256) for i in range(sz)]
    print("pad:", ''.join(hex(i)[2:] for i in pad))
    
    while message == "":
        with open('words', 'r') as f:
            words = f.readlines()
            for word in words:
                word = word.strip()
                if random() < 0.0001 and len(word) == sz:
                    message = word
                    print("message:", message)
                    message = [ord(c) for c in message]
                    break
    
    
    
    ### ENCRYPT ###
    c = [c0]
    for i in range(sz):
        c.append(message[i] ^ ( (pad[i] ^ c[i]) % 256 ))
    c = ''.join([('0' + hex(i)[2:])[-2:] for i in c[1:]])
    print("Encrypted CipherText:", c)
    
    ### DECRYPT ###
    m = []
    c = [c0] + [int(c[i:i+2], 16) for i in range(0, sz << 1, 2)]
    for i in range(sz):
        m.append(c[i+1] ^ ( (pad[i] ^ c[i]) % 256 ))
    print("Decrypted Plaintext:", ''.join([chr(i) for i in m]))
    
    