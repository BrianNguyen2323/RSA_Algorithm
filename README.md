# RSA_Algorithm
JHU Computer Organization Class Group Project - RSA Algorithm designed in ARM assembly to generate keys to encrypt and decrypt messages.


main control flow stucture

1. Prompt for p, validate (>2 && <50) -- retry on fail
2. Prompt for q, validate (>2 && <50) -- NOT THE SAME AS p
3. Compute n = p*q  and  phi = (p-1)(q-1)
4. Prompt for e, validate via cpubexp function -- retry on fail
5. Compute d via cprivexp
6. Print public key (e, n) and private key (d, n)
7. Prompt user for plaintext message
8. Encrypt char-by-char, write integer values into encrypted.txt
9. Print encrypted.txt contents to terminal for verification
10. Prompt user to verify the file and press 'd' to decrypt
11. Print plaintext to terminal, User can verify the decrypted file -- then exit




CHEAT SHEET OF COMBINATIONS 

p   11  11  13  17  17  19  23  29

q   13  17  17  19  23  29  29  31

e   7   3   5   5   5   7   11  13