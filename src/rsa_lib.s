.global gcd
.global primeCheck
.global calcTotient
.global eCheck

.global cpubexp
.global cprivexp
.global pow

.text

#
# Function Name:    gcd
# Author:           
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
	

primeCheck:
	CMP r0, #2
	BLT not_prime

	MOV r1, #2

check_loop:
	MUL r2, r1, r1
	CMP r2, r0
	BGT is_prime

	MOV r3, r0
	MOV r4, r1
	BL mod
	CMP r0, #0
	BEQ not_prime

	ADD r1, r1, #1
	B check_loop

is_prime:
	MOV r0, #1
	BX lr

not_prime:
	MOV r0, #0
	BX lr

calcTotient:
	SUB r0, r0, #1
	SUB r1, r1, #1
	MUL r0, r0, r1
	BX LR

eCheck:
	CMP r0, #1
	BLE invalid

	CMP r0, r1
	BGE invalid

	push {r1, lr}
	BL gcd
	pop {r1, lr}

	CMP r0, #1
	BNE invalid

	MOV r0, #1
	BX lr

// Brian - edited invalid to retore the stack
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

    MOV r4, r0	   //save base
    MOV r5, r2     //save modulus n
    MOV r6, r1     //loop counter = exponent
    MOV r3, #1     //result = 1

pow_loop:
    CMP r6, #0
    BEQ pow_done

    MUL r0, r3, r4		//r0 = result * base
    MOV r1, r5          //r1 = n
    BL mod              //r0 = (result * base) mod n
    MOV r3, r0          //update result

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
# Input:            public key exponent candidate (e) and totient phi_n = (p-1)(q-1)
# Output:           boolean return if public key exponent (e) is valid. 1 is valid, 0 is invalid
#

cpubexp: 
	# push the stack
    SUB sp, sp, #12
    STR lr, [sp]
    STR r4, [sp, #4]
    STR r5, [sp, #8]

    MOV r4, r0    // e input from user
    MOV r5, r1    // totient

    # check if e is a positive integer
    CMP r4, #1
    BLE invalid    // e must be > 1

    # check if e < totient
    CMP r4, r5
    BGE invalid    // branch to invalid if e >= phi_n (totient)

    # gcd check
    MOV r0, r4
    MOV r1, r5
    BL gcd
    CMP r0, #1
    BEQ valid    // gcd returns 1 which means co-prime
    B invalid    // anything else, e fails


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
