.text
.global main

main:

// ---------------------------------------------
// Main menu loop - keeps running until user exits
// ---------------------------------------------
loop:
	LDR r0, =menu
	BL printf

	LDR r0, =fmt
	LDR r1, =choice
	BL scanf

	BL flush_input           // clear leftover newline after every menu read

	LDR r1, =choice
	LDR r0, [r1]

	CMP r0, #1
	BEQ generate_keys
	CMP r0, #2
	BEQ encrypt_option
	CMP r0, #3
	BEQ decrypt_option
	CMP r0, #4
	BEQ exit_program

	// invalid menu choice - re-prompt
	LDR r0, =invalid_choice_msg
	BL printf
	B loop


// ---------------------------------------------
// Option 1 - Generate Keys
// ---------------------------------------------
generate_keys:

enter_p:
	LDR r0, =prompt_p
	BL printf

	LDR r0, =fmt
	LDR r1, =p
	BL scanf

	// check if p is prime
	LDR r1, =p
	LDR r0, [r1]
	BL primeCheck
	CMP r0, #0
	BEQ bad_p

enter_q:
	LDR r0, =prompt_q
	BL printf

	LDR r0, =fmt
	LDR r1, =q
	BL scanf

	// check if q is prime
	LDR r1, =q
	LDR r0, [r1]
	BL primeCheck
	CMP r0, #0
	BEQ bad_q

	// compute n = p * q
	LDR r1, =p
	LDR r0, [r1]             // r0 = p value
	LDR r1, =q
	LDR r1, [r1]             // r1 = q value
	MUL r2, r0, r1           // r2 = p * q
	LDR r3, =n
	STR r2, [r3]             // store n

	// n must be > 127 so all standard ASCII characters (up to 126) satisfy m < n
	CMP r2, #127
	BLE n_too_small

	// compute phi = (p-1)(q-1) via calcTotient
	LDR r1, =p
	LDR r0, [r1]             // r0 = p value
	LDR r1, =q
	LDR r1, [r1]             // r1 = q value
	BL calcTotient           // r0 = (p-1)(q-1)
	LDR r1, =phi
	STR r0, [r1]             // store phi

	// guard: phi must be > 2 - if phi <= 2 no valid e can exist
	// example: p=2, q=3 gives phi=2 and 1 < e < 2 has no integer solution
	CMP r0, #2
	BLE phi_too_small

enter_e:
	// show phi so the user knows the valid range for e
	LDR r0, =msg_phi
	LDR r1, =phi
	LDR r1, [r1]
	BL printf

	LDR r0, =prompt_e
	BL printf

	LDR r0, =fmt
	LDR r1, =e
	BL scanf

	// validate e - must satisfy 1 < e < phi and gcd(e, phi) = 1
	LDR r1, =e
	LDR r0, [r1]             // r0 = e value
	LDR r1, =phi
	LDR r1, [r1]             // r1 = phi value
	BL cpubexp               // r0 = 1 if valid, 0 if invalid
	CMP r0, #0
	BEQ bad_e

	// compute d = private key exponent via cprivexp(e, phi)
	LDR r1, =e
	LDR r0, [r1]             // r0 = e value
	LDR r1, =phi
	LDR r1, [r1]             // r1 = phi value
	BL cprivexp              // r0 = d
	LDR r1, =d
	STR r0, [r1]             // store d

	// set keys_ready flag so encrypt and decrypt can proceed
	MOV r0, #1
	LDR r1, =keys_ready
	STR r0, [r1]

	// display keys generated confirmation
	LDR r0, =keys_gen_msg
	BL printf

	// display public key: (e, n)
	LDR r0, =msg_pubkey
	LDR r1, =e
	LDR r1, [r1]             // r1 = e
	LDR r2, =n
	LDR r2, [r2]             // r2 = n
	BL printf

	// display private key: (d, n)
	LDR r0, =msg_privkey
	LDR r1, =d
	LDR r1, [r1]             // r1 = d
	LDR r2, =n
	LDR r2, [r2]             // r2 = n
	BL printf

	B loop

bad_p:
	LDR r0, =notprime_msg
	BL printf
	BL flush_input           // drain leftover chars (e.g. from "1.5" input)
	B enter_p

bad_q:
	LDR r0, =notprime_msg
	BL printf
	BL flush_input
	B enter_q

bad_e:
	LDR r0, =invalid_e_msg
	BL printf
	BL flush_input
	B enter_e

n_too_small:
	// n = p*q is too small - RSA requires m < n for all message characters
	// printable ASCII goes up to 126, so n must be > 127
	LDR r0, =n_too_small_msg
	LDR r1, =n
	LDR r1, [r1]             // pass n value so user sees what it computed to
	BL printf
	B enter_p                // pick larger primes

phi_too_small:
	// phi <= 2 means no integer e can satisfy 1 < e < phi
	// happens when p=2 and q=3 (phi=2) or p=q=2 (phi=1)
	// solution: choose larger primes
	LDR r0, =phi_too_small_msg
	BL printf
	B enter_p                // restart key generation from p


// ---------------------------------------------
// Option 2 - Encrypt a Message
// ---------------------------------------------
encrypt_option:
	// guard - keys must be generated first
	LDR r1, =keys_ready
	LDR r0, [r1]
	CMP r0, #0
	BEQ no_keys_error

	// prompt user and read message into msg_buf
	LDR r0, =encrypt_prompt
	BL printf

	LDR r0, =fmt_str         // " %255[^\n]" reads full line including spaces
	LDR r1, =msg_buf
	BL scanf

	BL flush_input           // clear trailing newline

	// call encrypt(msg_buf pointer, e, n)
	LDR r0, =msg_buf         // r0 = pointer to message buffer
	LDR r1, =e
	LDR r1, [r1]             // r1 = e value
	LDR r2, =n
	LDR r2, [r2]             // r2 = n value
	BL encrypt

	LDR r0, =encrypt_done_msg
	BL printf
	B loop


// ---------------------------------------------
// Option 3 - Decrypt a Message
// ---------------------------------------------
decrypt_option:
	// guard - keys must be generated first
	LDR r1, =keys_ready
	LDR r0, [r1]
	CMP r0, #0
	BEQ no_keys_error

	// print header - decrypted chars print inline after this
	LDR r0, =decrypt_header_msg
	BL printf
	MOV r0, #0               // fflush(NULL) - flush all stdio buffers
	BL fflush               // ensures header appears before raw SVC writes

	// call decrypt(d, n) - returns 0 on success, -1 if file not found
	LDR r0, =d
	LDR r0, [r0]             // r0 = d value
	LDR r1, =n
	LDR r1, [r1]             // r1 = n value
	BL decrypt

	// check return: negative = encrypted.txt not found
	CMP r0, #0
	BMI no_encrypted_error

	LDR r0, =decrypt_done_msg
	BL printf
	B loop

no_encrypted_error:
	LDR r0, =no_encrypted_msg
	BL printf
	B loop


// ---------------------------------------------
// Error - no keys generated yet
// ---------------------------------------------
no_keys_error:
	LDR r0, =no_keys_msg
	BL printf
	B loop


// ---------------------------------------------
// Option 4 - Exit
// ---------------------------------------------
exit_program:
	MOV r7, #1
	SWI 0


// ---------------------------------------------
// flush_input - drains stdin up to and including the next newline
// Fixes infinite loops caused by leftover characters in the buffer
// (e.g. user enters "1.5" - scanf reads "1", leaves ".5\n" behind)
// ---------------------------------------------
flush_input:
	SUB sp, sp, #4
	STR lr, [sp]

flush_loop:
	BL getchar               // read one character from stdin
	CMP r0, #10              // '\n' - end of the bad input
	BEQ flush_done
	CMP r0, #-1              // EOF
	BEQ flush_done
	B flush_loop

flush_done:
	LDR lr, [sp]
	ADD sp, sp, #4
	BX lr


// ---------------------------------------------
// Data section - all string literals
// ---------------------------------------------
.data

menu: .asciz "\nRSA Menu:\n1. Generate Keys\n2. Encrypt a Message\n3. Decrypt a Message\n4. Exit\nChoice: "

prompt_p: .asciz "Enter p (prime, < 50): "
prompt_q: .asciz "Enter q (prime, < 50): "
prompt_e: .asciz "Enter e: "

fmt:     .asciz "%d"
fmt_str: .asciz " %255[^\n]"

decrypt_header_msg: .asciz "Decrypted message: "
no_encrypted_msg:   .asciz "Error: encrypted.txt not found. Please encrypt a message first.\n"
encrypt_prompt:   .asciz "Enter message to encrypt: "
encrypt_done_msg: .asciz "Encryption complete. Cipher values written to encrypted.txt\n"
decrypt_done_msg: .asciz "\nDecryption complete. Plaintext written to plaintext.txt\n"

keys_gen_msg: .asciz "Keys generated successfully!\n"
msg_pubkey:   .asciz "  Public key  (e, n) = (%d, %d)\n"
msg_privkey:  .asciz "  Private key (d, n) = (%d, %d)\n"

msg_phi:           .asciz "  phi(n) = %d  (e must be co-prime to phi, 1 < e < phi)\n"

n_too_small_msg:   .asciz "Error: n = p*q = %d is too small. Need n > 127 for ASCII. Choose larger primes.\n"
notprime_msg:      .asciz "Not a valid prime in range [2,50). Try again.\n"
invalid_e_msg:     .asciz "Error: e is invalid. Please re-enter e.\n"
phi_too_small_msg: .asciz "Error: phi(n) is too small - no valid e can exist (try larger primes).\n"
no_keys_msg:       .asciz "Error: No keys found. Please generate keys first (Option 1).\n"
invalid_choice_msg: .asciz "Invalid choice. Please enter 1 - 4.\n"


// ---------------------------------------------
// BSS section - runtime variables (zeroed on start)
// ---------------------------------------------
.bss
p:          .skip 4
q:          .skip 4
phi:        .skip 4
e:          .skip 4
n:          .skip 4
d:          .skip 4
choice:     .skip 4
keys_ready: .skip 4
msg_buf:    .skip 256