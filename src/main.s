.text
.global main
main:
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
		BEQ encrypt_message
		B exit

	generate_keys:
		# Read p
		LDR r0, =prompt_p
		BL printf

		LDR r0, =fmt
		LDR r1, =p
		BL scanf
	
		# Read q
		LDR r0, =prompt_q
		BL printf

		LDR r0, =fmt
		LDR r1, =q
		BL scanf

		# Check p prime
		LDR r1, =p
		LDR r0, [r1]
		BL primeCheck
		CMP r0, #0
		BEQ not_prime

		# Check q prime
		LDR r1, =q
		LDR r0, [r1]
		BL primeCheck
		CMP r0, #0
		BEQ not_prime

		// compute n = p * q
		LDR r1, =p
		LDR r0, [r1]
		LDR r1, =q
		LDR r1, [r1]
		MUL r2, r0, r1
		LDR r3, =n
		STR r2, [r3]

		# Compute phi = (p-1)(q-1)
		LDR r2, =p
		LDR r3, =q
		BL calcTotient
		LDR r4, =phi
		STR r0, [r4]

		# Read e
		LDR r0, =prompt_e
		BL printf

		LDR r0, =fmt
		LDR r1, =e
		BL scanf

		// check e against the totient using cpubexp
		LDR r1, =e
		LDR r0, [r1]		// r0 = e value
		LDR r1, =phi
		LDR r1, [r1]		// r1 = phi_n value
		BL cpubexp
		CMP r0, #0
		BEQ invalid_e

		LDR r0, =success_msg
		BL printf
		B loop

	not_prime:
		LDR r0, =notprime_msg
		BL printf
		B loop

	invalid_e:
		LDR r0, =invalide_msg
		BL printf
		B loop

	encrypt_message:
		// prompt user for message
		LDR r0, =encrypt_prompt
		BL printf

		// read the full message line (including spaces) into msg_buf
		LDR r0, =fmt_str
		LDR r1, =msg_buf
		BL scanf

		// load e and n values from memory
		LDR r1, =e
		LDR r4, [r1]		// r4 = e value
		LDR r1, =n
		LDR r5, [r1]		// r5 = n value

		// call encrypt(msg_buf ptr, e, n)
		LDR r0, =msg_buf	// r0 = pointer to message
		MOV r1, r4		// r1 = e
		MOV r2, r5		// r2 = n
		BL encrypt

		LDR r0, =encrypt_done_msg
		BL printf
		B loop

	exit:
		MOV r7, #1
		SWI 0

.data
menu: .asciz "Menu Options\n1. Generate Keys\n2. Encrypt a Message\n3. Quit\nChoice: "
prompt_p: .asciz "Enter p (<50): "
prompt_q: .asciz "Enter q (<50): "
prompt_e: .asciz "Enter e: "

fmt: .asciz "%d"
fmt_str: .asciz " %255[^\n]"

encrypt_prompt: .asciz "Enter message to encrypt: "
encrypt_done_msg: .asciz "Message encrypted and written to encrypted.txt\n"

notprime_msg: .asciz "Error: p or q not prime \n"
invalide_msg: .asciz "Error: invalid e\n"
success_msg: .asciz "Keys generated successfully!\n"

.bss
p: .skip 4
q: .skip 4
phi: .skip 4
e: .skip 4
n: .skip 4
choice: .skip 4
msg_buf: .skip 256
