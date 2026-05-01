# RSA Algorithm — ARM Assembly

**JSU Computer Organization Class Group Project**
Implements RSA key generation, encryption, and decryption entirely in ARM assembly language.

---

## How to Build and Run

```bash
# Strip Windows formatting artifacts and assemble + link
dos2unix src/main.s src/rsa_lib.s
make

# Or just make (the Makefile runs dos2unix automatically)
make

# Run the program
./program
```

---

## Program Structure

The program is split into two files:

### `main.s` — Frontend / User Interface
Displays a menu loop and handles all user input. Calls library functions from `rsa_lib.s` and passes computed values between menu options.

**Menu options:**
1. Generate Keys
2. Encrypt a Message
3. Decrypt a Message
4. Exit

**Generate Keys flow:**
1. Prompt for p — validate prime, re-prompt on failure
2. Prompt for q — validate prime, re-prompt on failure
3. Compute n = p * q — reject and restart if n <= 127
4. Compute phi(n) = (p-1)(q-1) — reject and restart if phi <= 2
5. Display phi(n) and prompt for e — validate via `cpubexp`, re-prompt on failure
6. Compute private key d via `cprivexp`
7. Set `keys_ready` flag and display:
   - `Public key  (e, n) = (e, n)`
   - `Private key (d, n) = (d, n)`
8. Return to menu

**Encrypt flow:**
- Requires keys to be generated first (checks `keys_ready` flag)
- Prompts for plaintext message (up to 255 characters)
- Calls `encrypt(msg_buf, e, n)` in rsa_lib.s
- Confirmation printed on completion

**Decrypt flow:**
- Requires keys to be generated first
- Calls `decrypt(d, n)` in rsa_lib.s
- Decrypted message is printed to the console inline
- Confirmation printed on completion

---

### `rsa_lib.s` — Backend / Library Functions

| Function | Purpose |
|---|---|
| `gcd` | Euclidean algorithm — finds GCD of two integers |
| `mod` | Repeated subtraction — computes a mod b |
| `primeCheck` | Trial division up to sqrt(n) — returns 1 if prime, 0 if not |
| `calcTotient` | Computes phi(n) = (p-1)(q-1) |
| `cpubexp` | Validates e: checks e > 1, e < phi, and gcd(e, phi) = 1 |
| `cprivexp` | Computes d = (1 + x * phi) / e by iterating x = 1, 2, 3 ... |
| `pow` | Modular exponentiation — computes base^exp mod n via repeated multiplication |
| `encrypt` | Opens encrypted.txt, encrypts each ASCII character as c = m^e mod n, writes space-separated cipher values |
| `decrypt` | Opens encrypted.txt, parses space-separated integers, decrypts each as m = c^d mod n, writes to plaintext.txt and prints to console |
| `write_num` | Converts an integer to a decimal string and writes it to a file descriptor (used internally by encrypt) |

---

## Constraints

| Constraint | Value | Reason |
|---|---|---|
| p, q range | 2 to 49 (prime, < 50) | Assignment requirement |
| n = p * q | Must be **> 127** | RSA requires m < n for every plaintext character. Printable ASCII goes up to 126, so n must exceed 127 for encryption to be mathematically correct |
| phi(n) | Must be **> 2** | If phi <= 2 there is no integer e satisfying 1 < e < phi |
| e | 1 < e < phi(n) and gcd(e, phi(n)) = 1 | Standard RSA public exponent constraints |
| Message length | Max **255 characters** | Fixed buffer size in `msg_buf` (.bss) |
| Message characters | Standard printable ASCII (space through ~) | Values 32–126; all must be < n |
| encrypted.txt | Overwritten on each encrypt | O_TRUNC flag used on open |
| plaintext.txt | Overwritten on each decrypt | O_TRUNC flag used on open |

---

## Key Generation Cheat Sheet

All combinations below satisfy n > 127. Choose e values that are co-prime to phi(n).

| p  | q  | n    | phi(n) | Valid e examples |
|----|-----|------|--------|-----------------|
| 11 | 13  | 143  | 120    | 7, 11, 13       |
| 11 | 17  | 187  | 160    | 3, 7, 9         |
| 13 | 17  | 221  | 192    | 5, 7, 11        |
| 17 | 19  | 323  | 288    | 5, 7, 11        |
| 17 | 23  | 391  | 352    | 3, 5, 7         |
| 19 | 29  | 551  | 504    | 5, 11, 13       |
| 23 | 29  | 667  | 616    | 3, 5, 9         |
| 29 | 31  | 899  | 840    | 13, 11, 17      |

> **Note:** e = 7 does **not** work for p=19, q=29 (phi=504, gcd(7,504)=7).
> e = 11 does **not** work for p=23, q=29 (phi=616, gcd(11,616)=11).
> The program will reject invalid e values and re-prompt.

---

## File Output

| File | Contents |
|---|---|
| `encrypted.txt` | Space-separated decimal cipher values, one per original character |
| `plaintext.txt` | Recovered plaintext characters written after decryption |

**Example** — encrypting `"hi"` with p=11, q=13, e=7, n=143:
- `'h'` = ASCII 104 → 104^7 mod 143 → cipher value written to file
- `'i'` = ASCII 105 → 105^7 mod 143 → cipher value written to file
- `encrypted.txt` contains two space-separated integers

---

## Known Limitations

- Fractional inputs (e.g. `11.5`) are handled — the integer part is used and the decimal remainder is flushed from stdin before the next prompt
- Selecting decrypt before generating keys shows an error and returns to the menu
- Selecting decrypt before encrypting (no `encrypted.txt`) shows an error and returns to the menu
- Generating new keys does not invalidate previously encrypted files — decrypting with mismatched keys produces garbled output