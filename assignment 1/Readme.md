# Vigenere Cipher

### Part 1
We take a plaintext as input from the input.txt file and encrypt it with a key from the key.txt file. This part is simple since it uses a cyclic shift to change the characters using the key provided.
### Part 2
We try to decipher the text encrypted in part 1 we first need to estimate the length of the key. We use kaisiski examination to do so
##### Kaisiski Examitaion
Kasiski Examination is a method for breaking Vigenère ciphers by exploiting the repetition of substrings in the ciphertext caused by repeated use of the same key. It involves finding repeated sequences of characters in the ciphertext and then analyzing the distances between these repetitions.

1. Find Repeated Substrings:
   - Iterate through the ciphertext and identify sequences of characters that repeat.
   - Record the positions of these repetitions.

2. Calculate Distances:
   - For each repeated substring, calculate the distances between consecutive occurrences.
   - These distances may indicate potential key lengths since they could correspond to the length of the repeating key.

3. Factorize Distances:
   - Factorize the distances to identify common factors.
   - Common factors may represent the lengths of the repeating key used in the Vigenère cipher.

By identifying these potential key lengths, Kasiski Examination helps in narrowing down the possibilities for the length of the key used in the Vigenère cipher.

For each possible key length, the program guesses the key using frequency analysis. It identifies the most common character in each position of the key and assumes it corresponds to 'E', the most frequent letter in English. Then, it calculates the shift needed to transform that character into 'E', and hence guesses the key.

We decrypt the program using the guessed key for all the key lengths we generated.

