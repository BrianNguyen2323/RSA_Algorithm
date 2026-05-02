.global gcd
.global primeCheck
.global calcTotient
.global cpubexp
.global cprivexp
.global pow
.global encrypt
.global decrypt

.text

#
# Function Name:    gcd
# Author:           Brian Nguyen
# Purpose:          Computes the greatest common divisor of two integers.
#                   Used to verify that e and phi_n share no common factors (gcd == 1 means co-prime).
# Input:            r0 = a (first integer)
#                   r1 = b (second integer)
# Output:           r0 = greatest common divisor of a and b
#
gcd:
	# push the stack
	SUB sp, sp, #4
	STR lr, [sp]

	gcd_loop:
		CMP r1, #0
		BEQ done_gcd

		MOV r2, r1
		BL mod
		MOV r1, r0
		MOV r0, r2
		B gcd_loop

	done_gcd:
		# pop the stack
		LDR lr, [sp]
		ADD sp, sp, #4

		BX lr

#
# Function Name:    mod
# Author:           Brian Nguyen
# Purpose:          Computes the remainder of integer division using repeated subtraction.
#                   Used internally by gcd, primeCheck, pow, cprivexp, and decrypt.
# Input:            r0 = dividend
#                   r1 = divisor
# Output:           r0 = remainder (r0 mod r1)
#
mod:
	CMP r1, #0
	BEQ done_mod

mod_loop:
	CMP r0, r1
	BLT done_mod
	SUB r0, r0, r1
	B mod_loop

done_mod:
	BX lr
	

#
# Function Name:    primeCheck
# Author:           Brian Nguyen
# Purpose:          Tests whether a given integer is prime using trial division
#                   up to sqrt(n). Returns 1 if prime, 0 if not.
# Input:            r0 = candidate integer to test
# Output:           r0 = 1 if prime, 0 if not prime
#
primeCheck:
	# push the stack
	SUB sp, sp, #4
	STR lr, [sp]

	CMP r0, #2
	BLT not_prime

	MOV r1, #2

check_loop:
	MUL r2, r1, r1
	CMP r2, r0
	BGT is_prime

	MOV r3, r0
	BL mod
	CMP r0, #0
	BEQ not_prime

	MOV r0, r3
	ADD r1, r1, #1
	B check_loop

is_prime:
	MOV r0, #1

	# pop the stack
	LDR lr, [sp]
	ADD sp, sp, #4
	
	BX lr

not_prime:
	MOV r0, #0

	# pop the stack
	LDR lr, [sp]
	ADD sp, sp, #4

	BX lr

#
# Function Name:    calcTotient
# Author:           Brian Nguyen
# Purpose:          Computes Euler's totient phi(n) = (p-1)(q-1).
#                   Used during key generation to determine the valid range for e.
# Input:            r0 = p (first prime)
#                   r1 = q (second prime)
# Output:           r0 = phi(n) = (p-1)(q-1)
#
calcTotient:
	SUB r0, r0, #1
	SUB r1, r1, #1
	MUL r0, r0, r1
	BX LR


invalid:
	MOV r0, #0
    LDR lr, [sp]
    LDR r4, [sp, #4]
    LDR r5, [sp, #8]
    ADD sp, sp, #12
	BX lr

#
# Function Name:    pow
# Author:           Brian Nguyen
# Purpose:          Performs modular exponentiation — computes base^exp mod n.
#                   Used for encryption (c = m^e mod n) and decryption (m = c^d mod n).
# Input:            r0 = base  (ASCII char value for encryption, cipher value for decryption)
#                   r1 = exp   (public exponent e for encryption, private exponent d for decryption)
#                   r2 = n     (modulus, computed as p * q during key generation)
# Output:           r0 = result of base^exp mod n
#                        (cipher value c when encrypting, plaintext ASCII value m when decrypting)
#

pow:
	# Function Register Dictionary:
	#	r4 - base (ASCII char value for encryption, cipher value for decryption)
	#	r5 - modulus n (p * q)
	#	r6 - loop counter (counts down from exponent to 0)

	# push the stack
    SUB sp, sp, #16
    STR lr, [sp]
    STR r4, [sp, #4]
    STR r5, [sp, #8]
    STR r6, [sp, #12]

    MOV r4, r0          // save base
    MOV r5, r2          // save modulus n
    MOV r6, r1          // loop counter = exponent
    MOV r3, #1          // result = 1

pow_loop:
    CMP r6, #0
    BEQ pow_done

    MUL r0, r3, r4      // r0 = result * base
    MOV r1, r5          // r1 = n
    BL mod              // r0 = (result * base) mod n
    MOV r3, r0          // update result

    SUB r6, r6, #1
    B pow_loop

pow_done:
    MOV r0, r3

	# pop the stack
    LDR lr, [sp]
    LDR r4, [sp, #4]
    LDR r5, [sp, #8]
    LDR r6, [sp, #12]
    ADD sp, sp, #16
    BX lr

/*
* Instructions detailed for a cpubexp function so what I'm thinking for structure:
* main.s will display options and if generate keys option is selected
* then main will prompt for p and q integers.
* A loop will run BL to a check for each p and q until a valid p and q are stored
* 
* main.s will have p and q stored in registers which will then BL to the calcTotient
* Then run a loop until a valid e value is entered from the user, BL to cpubexp passing two parameters: e and totient
*
* cpubexp will perform the two checks and final check will call to the gcd function 
*/
#
# Function Name:    cpubexp
# Author:           Brian Nguyen
# Purpose:          Validates a candidate public key exponent e against three condition checks
#                   conditions: e > 1, e < phi_n, and gcd(e, phi_n) == 1
# Input:            r0 = e     (public key exponent candidate)
#                   r1 = phi_n (totient, (p-1)(q-1))
# Output:           boolean return if public key exponent (e) is valid. 1 is valid, 0 is invalid
#

cpubexp: 
	# push the stack
    SUB sp, sp, #12
    STR lr, [sp]
    STR r4, [sp, #4]
    STR r5, [sp, #8]

    MOV r4, r0          // e input from user
    MOV r5, r1          // totient

    # check if e is a positive integer
    CMP r4, #1
    BLE invalid         // e must be > 1

    # check if e < totient
    CMP r4, r5
    BGE invalid         // branch to invalid if e >= phi_n (totient)

    # gcd check
    MOV r0, r4
    MOV r1, r5
    BL gcd
    CMP r0, #1
    BEQ valid           // gcd returns 1 which means co-prime
    B invalid           // anything else, e fails


#
# Function Name:    valid
# Author:           Brian Nguyen
# Purpose:          returns to main a valid pass for e
# 
valid:
    MOV r0, #1

	# pop the stack
    LDR lr, [sp]
    LDR r4, [sp, #4]
    LDR r5, [sp, #8]
    ADD sp, sp, #12
    BX lr

    
// removed .data line since it is not used in rsa_lib.s

#
# Function Name:    cprivexp
# Author:           Brian Nguyen and Ryan Rossman
# Purpose:          Calculates the private key exponent d such that de ≡ 1 (mod Φ(n)).
#                   Iterates x = 1, 2, 3, ... computing (1 + x * Φ(n)) until the result
#                   is evenly divisible by e, then returns d = (1 + x * Φ(n)) / e.
# Input:            r0 = e     (public key exponent, validated by cpubexp)
#                   r1 = phi_n (totient, Φ(n) = (p-1)(q-1))
# Output:           r0 = d     (private key exponent)
#

cprivexp:
	# Function Register Dictionary:
	#	r4 - e (public key exponent)
	#	r5 - phi_n (totient)
	#	r6 - x (loop counter, increments until d is found)

	# push the stack
	SUB sp, sp, #16
	STR lr, [sp]
	STR r4, [sp, #4]
	STR r5, [sp, #8]
	STR r6, [sp, #12]

	MOV r4, r0       
	MOV r5, r1        
	MOV r6, #1          // start x variable at 1

cprivexp_loop:
	MUL r3, r6, r5      // r3 = x * phi_n
	ADD r3, r3, #1      // r3 = 1 + x * phi_n (numerator)

	MOV r0, r3          // dividend = numerator
	MOV r1, r4          // divisor = e
	BL mod              // r0 = numerator mod e

	CMP r0, #0          // r0 should have the mod result
	BEQ found_d         // remainder is 0, numerator divisible by e

	ADD r6, r6, #1      // incrementing x by 1 if d (private exponent) was not found
	CMP r6, #1000       // safety guard - bail out if no d found within 1000 iterations
	BGT cprivexp_fail
	B cprivexp_loop

found_d:
	# r3 still holds numerator (mod only touched r0 and r1)
	# compute d = numerator / e via repeated subtraction
	MOV r0, #0          // d = 0

div_loop:
	CMP r3, r4          // while numerator (r3) >= e
	BLT cprivexp_done
	SUB r3, r3, r4      // numerator (r3) -= e
	ADD r0, r0, #1      // d++, incrementing 1 to the result to show one successful division
	B div_loop

cprivexp_done:
	# pop the stack
	LDR lr, [sp]
	LDR r4, [sp, #4]
	LDR r5, [sp, #8]
	LDR r6, [sp, #12]
	ADD sp, sp, #16
	BX lr

cprivexp_fail:
	// no valid d found within iteration limit - return 0 to signal failure
	LDR lr, [sp]
	LDR r4, [sp, #4]
	LDR r5, [sp, #8]
	LDR r6, [sp, #12]
	ADD sp, sp, #16
	MOV r0, #0          // return 0 indicates failure
	BX lr

#
# Function Name:    encrypt
# Author:           Brian Nguyen
# Purpose:          Encrypts a plaintext message character by character using the public key (e, n).
#                   Determines the ASCII value of each character and applies c = m^e mod n.
#                   Cipher values are written space-separated to encrypted.txt.
#                   The file is opened before writing and closed when complete.
# Prerequisite:     Keys must already be generated — n, e, and d must be computed and stored
#                   before this function is called.
# Input:            r0 = pointer to message buffer (read and passed in by main.s)
#                   r1 = e  (public key exponent)
#                   r2 = n  (modulus, p * q)
# Output:           No return value. Space-separated cipher values written to encrypted.txt.
#

encrypt:

	# Function Register Dictionary:
	#	r4 - e (public key exponent)
	#	r5 - n (modulus)
	#	r6 - file descriptor for encrypted.txt
	#	r8 - current position pointer in message buffer

	# push the stack
	SUB sp, sp, #20
	STR lr, [sp]
	STR r4, [sp, #4]
	STR r5, [sp, #8]
	STR r6, [sp, #12]
	STR r8, [sp, #16]

	MOV r8, r0          // save message buffer pointer
	MOV r4, r1          // save e
	MOV r5, r2          // save n

	// open encrypted.txt for writing (create if not exists, overwrite if exists)
	MOV r7, #5          // open syscall
	LDR r0, =enc_filename
	MOV r1, #1          // O_WRONLY - open for writing only
	ADD r1, r1, #64     // | O_CREAT  (0x40) - create the file if it doesn't exist
	ADD r1, r1, #512    // | O_TRUNC  (0x200) - if file already exists, clear it and start with a blank file
	MOV r2, #420        // permissions 0644 - read/write permissions
	SVC #0
	MOV r6, r0          // save file descriptor

encrypt_loop:
	LDRB r0, [r8]       // load current character byte

	CMP r0, #10         // newline = end of message
	BEQ encrypt_close
	CMP r0, #0          // null terminator = end of message
	BEQ encrypt_close

	// compute c = m^e mod n
	MOV r1, r4          // e
	MOV r2, r5          // n
	BL pow              // r0 = cipher value c

	// write cipher value as decimal to encrypted.txt
	MOV r1, r6          // pass file descriptor
	BL write_num        // writes integer r0 to fd r1

	// write a space separator between cipher values
	MOV r7, #4          // write syscall
	MOV r0, r6          // file descriptor
	LDR r1, =space_char
	MOV r2, #1          // one byte
	SVC #0

	ADD r8, r8, #1      // advance pointer to next character
	B encrypt_loop

encrypt_close:
	MOV r7, #6          // close syscall
	MOV r0, r6          // file descriptor
	SVC #0

	// pop the stack
	LDR lr, [sp]
	LDR r4, [sp, #4]
	LDR r5, [sp, #8]
	LDR r6, [sp, #12]
	LDR r8, [sp, #16]
	ADD sp, sp, #20
	BX lr


#
# Function Name:    write_num
# Author:			Brian Nguyen
# Purpose:          Converts integer r0 to a decimal string and writes it to file descriptor r1.
#                   Builds the digit string right-to-left in num_buf then writes it in one syscall.
# Input:            r0 = integer to write, r1 = file descriptor
# Output:           No return value.
#

write_num:
	SUB sp, sp, #12
	STR lr, [sp]
	STR r4, [sp, #4]
	STR r5, [sp, #8]

	MOV r4, r1          // save file descriptor
	LDR r5, =num_buf

	// place null at num_buf[4], then work right-to-left from num_buf[3]
	ADD r3, r5, #4
	MOV r1, #0
	STRB r1, [r3]       // null terminator
	SUB r3, r3, #1      // r3 points to ones digit position

	CMP r0, #0          // special case: value is zero
	BNE wn_loop
	MOV r1, #48         // ASCII '0'
	STRB r1, [r3]
	B wn_write

wn_loop:
	CMP r0, #0
	BEQ wn_write

	MOV r2, #0          // quotient = 0
wn_div:
	CMP r0, #10
	BLT wn_div_done
	SUB r0, r0, #10     // subtract 10 to find remainder
	ADD r2, r2, #1      // count how many times 10 fits
	B wn_div
wn_div_done:
	ADD r1, r0, #48     // remainder + '0' = digit character
	STRB r1, [r3]       // store digit
	SUB r3, r3, #1      // move pointer left for next digit
	MOV r0, r2          // quotient becomes new number
	B wn_loop

wn_write:
	ADD r3, r3, #1      // r3 now points to the first digit

	// length = (num_buf + 4) - r3
	LDR r2, =num_buf
	ADD r2, r2, #4
	SUB r2, r2, r3      // r2 = length of digit string

	MOV r7, #4          // write syscall
	MOV r0, r4          // file descriptor
	MOV r1, r3          // pointer to digit string
	SVC #0              // hand off to the kernel to write the data

	LDR lr, [sp]
	LDR r4, [sp, #4]
	LDR r5, [sp, #8]
	ADD sp, sp, #12
	BX lr


#
# Function Name:    decrypt
# Author:           Brian Nguyen
# Purpose:          Opens encrypted.txt and reads space-separated cipher values.
#                   Decrypts each value using the equation m = c^d mod n,
#                   where c is the cipher value, d is the private key exponent,
#                   and n is the modulus. Writes the recovered ASCII characters
#                   to plaintext.txt. Both files are opened before processing
#                   and closed when complete.
# Prerequisite:     Keys must already be generated and encrypted.txt must exist.
# Input:            r0 = d  (private key exponent)
#                   r1 = n  (modulus, p * q)
# Output:           No return value. Decrypted characters written to plaintext.txt.
#

decrypt:
	# Function Register Dictionary:
	#	r4 - d (private key exponent)
	#	r5 - n (modulus)
	#	r6 - file descriptor for encrypted.txt (read)
	#	r8 - file descriptor for plaintext.txt (write)
	#	r9 - current cipher value accumulator (built digit by digit from file)

	# push the stack
	SUB sp, sp, #24
	STR lr, [sp]
	STR r4, [sp, #4]
	STR r5, [sp, #8]
	STR r6, [sp, #12]
	STR r8, [sp, #16]
	STR r9, [sp, #20]

	MOV r4, r0          // save d
	MOV r5, r1          // save n

	// open encrypted.txt for reading
	MOV r7, #5          // open syscall
	LDR r0, =enc_filename
	MOV r1, #0          // O_RDONLY
	MOV r2, #0          // no mode needed for read-only open
	SVC #0
	MOV r6, r0          // save encrypted.txt file descriptor

	// negative fd means encrypted.txt does not exist
	CMP r6, #0
	BMI decrypt_no_file

	// open plaintext.txt for writing (create or overwrite)
	MOV r7, #5          // open syscall
	LDR r0, =plain_filename
	MOV r1, #1          // O_WRONLY
	ADD r1, r1, #64     // | O_CREAT  (0x40)
	ADD r1, r1, #512    // | O_TRUNC  (0x200)
	MOV r2, #420        // permissions 0644
	SVC #0
	MOV r8, r0          // save plaintext.txt file descriptor

	MOV r9, #0          // cipher value accumulator = 0

decrypt_read_loop:
	// read one byte at a time from encrypted.txt
	MOV r7, #3          // read syscall
	MOV r0, r6          // encrypted.txt fd
	LDR r1, =dec_buf    // single byte buffer
	MOV r2, #1          // read 1 byte
	SVC #0              // r0 = bytes read, 0 means EOF

	CMP r0, #0          // check for end of file
	BEQ decrypt_last    // handle the final number before closing

	LDR r3, =dec_buf
	LDRB r2, [r3]       // r2 = the byte just read from the file

	CMP r2, #32         // space = separator between cipher values
	BEQ decrypt_got_num
	CMP r2, #10         // newline = also treat as separator
	BEQ decrypt_got_num

	// it's a digit — build the number: current = current * 10 + (digit - '0')
	MOV r3, #10
	MUL r3, r9, r3      // r3 = accumulator * 10
	SUB r2, r2, #48     // r2 = digit value (ASCII digit - '0')
	ADD r9, r3, r2      // accumulator = (accumulator * 10) + digit
	B decrypt_read_loop

decrypt_got_num:
	CMP r9, #0          // skip if accumulator is 0 (consecutive spaces)
	BEQ decrypt_read_loop

	// compute m = c^d mod n
	MOV r0, r9          // base = cipher value c
	MOV r1, r4          // exp = d
	MOV r2, r5          // mod = n
	BL pow              // r0 = decrypted ASCII value m

	// write the recovered character byte to plaintext.txt
	LDR r3, =dec_buf
	STRB r0, [r3]       // store character in buffer
	MOV r7, #4          // write syscall
	MOV r0, r8          // plaintext.txt fd
	MOV r1, r3          // buffer address
	MOV r2, #1          // 1 byte
	SVC #0

	// also print decrypted character to console
	MOV r7, #4          // write syscall
	MOV r0, #1          // stdout fd
	MOV r1, r3          // dec_buf still holds the character
	MOV r2, #1          // 1 byte
	SVC #0

	MOV r9, #0          // reset accumulator for next cipher value
	B decrypt_read_loop

decrypt_last:
	// handle the final cipher value if the file had no trailing space
	CMP r9, #0
	BEQ decrypt_close

	MOV r0, r9
	MOV r1, r4
	MOV r2, r5
	BL pow

	LDR r3, =dec_buf
	STRB r0, [r3]
	MOV r7, #4
	MOV r0, r8
	MOV r1, r3
	MOV r2, #1
	SVC #0

	// also print to console
	MOV r7, #4          // write syscall
	MOV r0, #1          // stdout fd
	MOV r1, r3          // dec_buf still holds the character
	MOV r2, #1          // 1 byte
	SVC #0

decrypt_no_file:
	// encrypted.txt could not be opened - clean up stack and return error
	LDR lr, [sp]
	LDR r4, [sp, #4]
	LDR r5, [sp, #8]
	LDR r6, [sp, #12]
	LDR r8, [sp, #16]
	LDR r9, [sp, #20]
	ADD sp, sp, #24
	MOV r0, #-1         // error: file not found
	BX lr

decrypt_close:
	MOV r7, #6          // close syscall
	MOV r0, r6          // close encrypted.txt
	SVC #0
	MOV r7, #6
	MOV r0, r8          // close plaintext.txt
	SVC #0

	# pop the stack
	LDR lr, [sp]
	LDR r4, [sp, #4]
	LDR r5, [sp, #8]
	LDR r6, [sp, #12]
	LDR r8, [sp, #16]
	LDR r9, [sp, #20]
	ADD sp, sp, #24
	MOV r0, #0          // success return value
	BX lr


.data
enc_filename:    .asciz "encrypted.txt"
plain_filename:  .asciz "plaintext.txt"
space_char:      .ascii " "

.bss
num_buf:         .space 5
dec_buf:         .space 1
