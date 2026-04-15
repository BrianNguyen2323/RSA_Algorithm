.global gcd
.global primeCheck
.global calcTotient
.global eCheck

.text
gcd:
	gcd_loop:
		CMP r1, #0
		BEQ done_gcd

		MOV r2, r1
		BL mod
		MOV r1, r0
		MOV r0, r2
		B gcd_loop

	done_gcd:
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

invalid:
	MOV r0, #0
	BX lr

.data
