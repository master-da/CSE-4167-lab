import re
import string

def clean_text(text):
    cleaned_text = re.sub(r'[^A-Za-z]', '', text)
    return cleaned_text

def kasiski_examination(ciphertext):
    repeated_sequences = {}
    for i in range(len(ciphertext) - 2):
        sequence = ciphertext[i:i+3]
        if sequence in repeated_sequences:
            repeated_sequences[sequence].append(i)
        else:
            repeated_sequences[sequence] = [i]
    
    distances = {}
    for sequence, positions in repeated_sequences.items():
        if len(positions) > 1:
            distances[sequence] = [positions[i+1] - positions[i] for i in range(len(positions)-1)]
    
    factors = set()
    for sequence, dists in distances.items():
        for dist in dists:
            factors.update(factorize(dist))
    
    possible_lengths = [length for length in factors if length >= 3]
    return possible_lengths

def factorize(number):
    factors = []
    for i in range(1, int(number**0.5) + 1):
        if number % i == 0:
            factors.append(i)
            factors.append(number // i)
    return sorted(set(factors))

def guess_key(ciphertext, key_length):
    key = ''
    for offset in range(key_length):
        extracted_text = ''.join(ciphertext[i] for i in range(offset, len(ciphertext), key_length))
        freqs = {c: extracted_text.count(c) for c in string.ascii_uppercase}
        max_freq_char = max(freqs, key=freqs.get)
        shift = (ord(max_freq_char) - ord('E')) % 26
        key += chr((ord('A') + shift))
    return key

def vigenere_decrypt(ciphertext, key):
    decrypted_text = ''
    key_length = len(key)
    for i, char in enumerate(ciphertext):
        if char.isupper():
            shift = (ord(char) - ord(key[i % key_length]) + 26) % 26
            decrypted_text += chr(shift + ord('A'))
        elif char.islower():
            shift = (ord(char) - ord(key[i % key_length]) + 26) % 26
            decrypted_text += chr(shift + ord('a'))
    return decrypted_text

def main():
    with open('output.txt', 'r') as file:
        ciphertext = file.read()

    cleaned_ciphertext = clean_text(ciphertext)

    possible_lengths = kasiski_examination(cleaned_ciphertext)
    possible_lengths = list(filter(lambda x : x <= 6, sorted(set(kasiski_examination(cleaned_ciphertext))))) # Filter out larger keys to keep output nice looking

    print("Possible key lengths:")
    print(possible_lengths)

    best_guess = ()

    for length in possible_lengths:
        guessed_key = guess_key(cleaned_ciphertext, length)
        decrypted_text = vigenere_decrypt(cleaned_ciphertext, guessed_key)
        print(f"\nPredicted key: {guessed_key}")
        print("Decrypted message:")
        print(decrypted_text)

        if length == 4:
            best_guess = (guessed_key, decrypted_text)

    print("\n\n====================================================================")
    with open("../part 1/key.txt") as key_file:
        key = key_file.readline()
        print("Guesssed Key:", best_guess[0])
        print("Actual Key:", key)
        mismatch = 0
        for char in range(len(key)): 
            if not key[char] == best_guess[0][char]:
                mismatch += 1
        print(mismatch, "mismatch(es) out of", len(key), "characters")
        print("====================================================================")
    
    print("\n\n====================================================================")
    with open("../part 1/input.txt") as input_file:
        inp = input_file.readline()
        print("Guessed Input:", best_guess[1])
        print("Actual Input", inp)
        mismatch = 0
        for char in range(len(inp)):
            if not inp[char] == best_guess[1][char]:
                mismatch += 1
        print(mismatch, "mismatch(es) out of", len(inp), "characters")
        print("====================================================================")

if __name__ == "__main__":
    main()
