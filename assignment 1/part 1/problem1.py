import re

def read_input(filename):
    with open(filename, 'r') as file:
        text = file.read()
    
        cleaned_text = re.sub(r'[^a-zA-Z]', '', text)
        return cleaned_text 

def read_key(filename):
    with open(filename, 'r') as file:
        return file.read().strip() 

def vigenere_encrypt(plaintext, key):
    ciphertext = ''
    key_length = len(key)
    for i, char in enumerate(plaintext):
        if char.isupper():
            shift = ord(key[i % key_length]) - ord('A')
            encrypted_char = chr((ord(char) + shift - ord('A')) % 26 + ord('A'))
        elif char.islower():
            shift = ord(key[i % key_length]) - ord('a')
            encrypted_char = chr((ord(char) + shift - ord('a')) % 26 + ord('a'))
        else:
            encrypted_char = char 
        ciphertext += encrypted_char
    return ciphertext

def format_ciphertext(ciphertext):
    formatted_text = ' '.join([ciphertext[i:i+5] for i in range(0, len(ciphertext), 5)])
    return formatted_text

def vigenere_decrypt(ciphertext, key):
    plaintext = ''
    key_length = len(key)
    for i, char in enumerate(ciphertext):
        if char.isupper():
            shift = ord(key[i % key_length]) - ord('A')
            decrypted_char = chr((ord(char) - shift - ord('A')) % 26 + ord('A'))
        elif char.islower():
            shift = ord(key[i % key_length]) - ord('a')
            decrypted_char = chr((ord(char) - shift - ord('a')) % 26 + ord('a'))
        else:
            decrypted_char = char 
        plaintext += decrypted_char
    return plaintext

def main():

    plaintext = read_input('input.txt')
    key = read_key('key.txt')


    ciphertext = vigenere_encrypt(plaintext, key)


    formatted_ciphertext = format_ciphertext(ciphertext)
    with open('output.txt', 'w') as file:
        file.write(formatted_ciphertext)


    with open('output.txt', 'r') as file:
        ciphertext = file.read().replace(' ', '') 
    decrypted_text = vigenere_decrypt(ciphertext, key)


    print("Decrypted text:")
    print(decrypted_text)

if __name__ == "__main__":
    main()
