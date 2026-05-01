.text
.global main

main:

# Main menu loop — keeps running until user exits
loop:
	LDR r0, =menu
	BL printf

	LDR r0, =fmt
	LDR r1, =choice
	BL scanf

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

	// invalid menu choice — re-prompt
	LDR r0, =invalid_choice_msg
	BL printf
	B loop

# Option 1 — Generate Keys
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
	BEQ not_prime_p          // p not prime — re-enter p

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
	BEQ not_prime_q          // q not prime — re-enter q

	// compute n = p * q
	LDR r1, =p
	LDR r0, [r1]             // r0 = p value
	LDR r1, =q
	LDR r1, [r1]             // r1 = q value
	MUL r2, r0, r1           // r2 = p * q
	LDR r3, =n
	STR r2, [r3]             // store n

	// compute phi = (p-1)(q-1) via calcTotient
	LDR r1, =p
	LDR r0, [r1]             // r0 = p value
	LDR r1, =q
	LDR r1, [r1]             // r1 = q value
	BL calcTotient           // r0 = (p-1)(q-1)
	LDR r1, =phi
	STR r0, [r1]             // store phi

enter_e:
	LDR r0, =prompt_e
	BL printf

	LDR r0, =fmt
	LDR r1, =e
	BL scanf

	// validate e — must satisfy 1 < e < phi and gcd(e, phi) = 1
	LDR r1, =e
	LDR r0, [r1]             // r0 = e value
	LDR r1, =phi
	LDR r1, [r1]             // r1 = phi value
	BL cpubexp               // r0 = 1 if valid, 0 if invalid
	CMP r0, #0
	BEQ invalid_e            // e invalid — re-enter e

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

	// display all generated key values to the user
	LDR r0, =keys_gen_msg
	LDR r1, =n
	LDR r1, [r1]             // r1 = n
	LDR r2, =e
	LDR r2, [r2]             // r2 = e
	LDR r3, =d
	LDR r3, [r3]             // r3 = d
	BL printf

	B loop

not_prime_p:
	LDR r0, =notprime_p_msg
	BL printf
	B enter_p                // loop back to re-enter p

not_prime_q:
	LDR r0, =notprime_q_msg
	BL printf
	B enter_q                // loop back to re-enter q

invalid_e:
	LDR r0, =invalid_e_msg
	BL printf
	B enter_e                // loop back to re-enter e

# Option 2 — Encrypt a Message
encrypt_option:
	// guard — keys must be generated first
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

# Option 3 — Decrypt a Message
decrypt_option:
	// guard — keys must be generated first
	LDR r1, =keys_ready
	LDR r0, [r1]
	CMP r0, #0
	BEQ no_keys_error

	// call decrypt(d, n)
	LDR r0, =d
	LDR r0, [r0]             // r0 = d value
	LDR r1, =n
	LDR r1, [r1]             // r1 = n value
	BL decrypt

	LDR r0, =decrypt_done_msg
	BL printf
	B loop

# Error — no keys generated yet
no_keys_error:
	LDR r0, =no_keys_msg
	BL printf
	B loop

# Option 4 — Exit
exit_program:
	MOV r7, #1
	SWI 0

.data

menu: .asciz "\nRSA Menu:\n1. Generate Keys\n2. Encrypt a Message\n3. Decrypt a Message\n4. Exit\nChoice: "

prompt_p: .asciz "Enter p (prime, < 50): "
prompt_q: .asciz "Enter q (prime, < 50): "
prompt_e: .asciz "Enter e (must satisfy: 1 < e < phi and gcd(e, phi) = 1): "

fmt:     .asciz "%d"
fmt_str: .asciz " %255[^\n]"

encrypt_prompt:   .asciz "Enter message to encrypt: "
encrypt_done_msg: .asciz "Encryption complete. Cipher values written to encrypted.txt\n"
decrypt_done_msg: .asciz "Decryption complete. Plaintext written to plaintext.txt\n"

keys_gen_msg: .asciz "Keys generated successfully!\n  n = %d\n  e = %d\n  d = %d\n"

notprime_p_msg:   .asciz "Error: p is not prime. Please re-enter p.\n"
notprime_q_msg:   .asciz "Error: q is not prime. Please re-enter q.\n"
invalid_e_msg:    .asciz "Error: e is invalid. Please re-enter e.\n"
no_keys_msg:      .asciz "Error: No keys found. Please generate keys first (Option 1).\n"
invalid_choice_msg: .asciz "Invalid choice. Please enter 1 - 4.\n"

# BSS section — runtime variables (zeroed on start)
.bss
p:          .skip 4
q:          .skip 4
phi:        .skip 4
e:          .skip 4
n:          .skip 4
d:          .skip 4
choice:     .skip 4
keys_ready: .skip 4    // 0 = no keys, 1 = keys generated
msg_buf:    .skip 256