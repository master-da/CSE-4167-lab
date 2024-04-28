def strToHexAray(s):
    return [ord(c) for c in s]
def hexArrayToStr(h):
    return ''.join([chr(c) for c in h])

cipher_word1 = "e93ae9c5fc7355d5"
cipher_word2 = "f43afec7e1684adf"

if __name__ == "__main__":

    cipher_word1 = [int(cipher_word1[i:i+2], 16) for i in range(0, len(cipher_word1), 2)]
    cipher_word2 = [int(cipher_word2[i:i+2], 16) for i in range(0, len(cipher_word2), 2)]

    cipher_xor = [cipher_word1[i] ^ cipher_word2[i] for i in range(len(cipher_word1))]
    wordlist = []
    # filter a list of words of length 8 containing only alphabets
    with open('words', 'r') as f:
        words = f.readlines()        
        for word in words:
            word = word.strip()
            if len(word) == 8 and word.isalpha():
                wordlist.append(''.join([hex(ord(c))[2:] for c in word]))
    
    for word in wordlist:
        guessed_word1 = [int(word[i:i+2], 16) for i in range(0, len(word), 2)]
        guessed_word2 = [cipher_xor[i] ^ guessed_word1[i] for i in range(len(cipher_xor))]
        
        if ''.join([hex(i)[2:] for i in guessed_word2]) in wordlist:
            print(hexArrayToStr(guessed_word1), hexArrayToStr(guessed_word2))
            print("key =", hexArrayToStr([cipher_word1[i] ^ guessed_word1[i] for i in range(len(cipher_word1))]))
            break
        
    
    