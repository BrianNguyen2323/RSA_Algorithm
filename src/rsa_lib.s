.global gcd
.global primeCheck
.global calcTotient
.global eCheck
.global modexp
.global rsa_encrypt
.global rsa_decrypt
.global mod
.global cpubexp
.global cprivexp


.text

#---------------------------------------
# Function:  mod
# Inputs:    r0 = dividend, r1 = divisor
# Output:    r0 = remainder
# Clobbers:  r0 (result)
# ---------------------------------------

mod:
    CMP  r1, #0
    BEQ  done_mod           @ avoid divide-by-zero; return r0 unchanged
mod_loop:
    CMP  r0, r1
    BLT  done_mod
    SUB  r0, r0, r1
    B    mod_loop
done_mod:
    BX   lr

#---------------------------------------
# Function:  gcd
# Purpose:   Computes GCD(a, b) using the Euclidean algorithm
# Inputs:    r0 = a, r1 = b
# Output:    r0 = gcd(a, b)
#---------------------------------------
gcd:
    # Push stack 4
    SUB  sp, sp, #4
    STR  lr, [sp]

gcd_loop:
    CMP  r1, #0
    BEQ  done_gcd
    MOV  r2, r1             @ save current b in scratch r2
    BL   mod                @ r0 = a mod b
    MOV  r1, r0             @ new b = (old a) mod (old b)
    MOV  r0, r2             @ new a = old b
    B    gcd_loop

done_gcd:
    # Pop stack 4
    LDR  lr, [sp]
    ADD  sp, sp, #4
    BX   lr
	
#---------------------------------------
# Function:  primeCheck
# Purpose:   Tests whether a number is prime via trial division
# Input:     r0 = candidate integer
# Output:    r0 = 1 (prime)  or  0 (not prime)
#---------------------------------------
primeCheck:
    # Push stack 12
    SUB  sp, sp, #12
    STR  lr, [sp]
    STR  r3, [sp, #4]
    STR  r4, [sp, #8]

    CMP  r0, #2
    BLT  not_prime

    MOV  r3, r0             @ r3 = candidate (survives BL mod)
    MOV  r4, #2             @ r4 = divisor i = 2

pc_check_loop:
    MUL  r2, r4, r4         @ r2 = i * i
    CMP  r2, r3
    BGT  is_prime           @ i*i > candidate  =>  candidate is prime

    MOV  r0, r3             @ dividend = candidate
    MOV  r1, r4             @ divisor  = i
    BL   mod                @ r0 = candidate mod i

    CMP  r0, #0
    BEQ  not_prime          @ remainder 0  =>  divisible  =>  not prime

    ADD  r4, r4, #1         @ i++
    B    pc_check_loop

is_prime:
    MOV  r0, #1
    LDR  lr, [sp]
    LDR  r3, [sp, #4]
    LDR  r4, [sp, #8]
    ADD  sp, sp, #12
    BX   lr

not_prime:
    MOV  r0, #0
    LDR  lr, [sp]
    LDR  r3, [sp, #4]
    LDR  r4, [sp, #8]
    ADD  sp, sp, #12
    BX   lr

#---------------------------------------
# Function:  calcTotient
# Purpose:   Computes Euler's totient  phi(n) = (p-1)(q-1)
# Inputs:    r0 = p,  r1 = q
# Output:    r0 = phi(n)
#---------------------------------------

calcTotient:
    SUB  r0, r0, #1         @ p - 1
    SUB  r1, r1, #1         @ q - 1
    MUL  r0, r0, r1         @ (p-1)(q-1)
    BX   lr

#---------------------------------------
# Function:  eCheck
# Purpose:   Validates e:  e > 1,  e < phi(n),  gcd(e,phi)=1
# Inputs:    r0 = e,  r1 = phi(n)
# Output:    r0 = 1 (valid)  or  0 (invalid)
#---------------------------------------

eCheck:
    # Push stack 4
    SUB  sp, sp, #4
    STR  lr, [sp]

    BL   cpubexp            @ r0 = 1 or 0

    # Pop stack 4
    LDR  lr, [sp]
    ADD  sp, sp, #4
    BX   lr

#---------------------------------------
# Function:  cpubexp
# Author:    Brian Nguyen
# Purpose:   Validates a candidate public key exponent e:
#              (1) e > 1
#              (2) e < phi(n)
#              (3) gcd(e, phi(n)) == 1
# Inputs:    r0 = e (candidate),  r1 = phi(n) (totient)
# Output:    r0 = 1 (valid)  or  0 (invalid)
#---------------------------------------

cpubexp:
    # Push stack 12
    SUB  sp, sp, #12
    STR  lr, [sp]
    STR  r4, [sp, #4]
    STR  r5, [sp, #8]

    MOV  r4, r0             @ r4 = e
    MOV  r5, r1             @ r5 = phi(n)

    # Check 1: e > 1
    CMP  r4, #1
    BLE  cpubexp_invalid

    # Check 2: e < phi(n)
    CMP  r4, r5
    BGE  cpubexp_invalid

    # Check 3: gcd(e, phi(n)) == 1
    MOV  r0, r4
    MOV  r1, r5
    BL   gcd
    CMP  r0, #1
    BEQ  cpubexp_valid
    B    cpubexp_invalid

cpubexp_valid:
    MOV  r0, #1
    LDR  lr, [sp]
    LDR  r4, [sp, #4]
    LDR  r5, [sp, #8]
    ADD  sp, sp, #12
    BX   lr

cpubexp_invalid:
    MOV  r0, #0
    LDR  lr, [sp]
    LDR  r4, [sp, #4]
    LDR  r5, [sp, #8]
    ADD  sp, sp, #12
    BX   lr

#---------------------------------------
# Function:  cprivexp
# Purpose:   Computes private exponent d such that:
#              d * e ≡ 1 (mod phi(n))
#            Uses the formula:
#              d = (1 + x * phi(n)) / e
#            Iterates x = 1, 2, 3, ... until (1 + x*phi(n))
#            is exactly divisible by e.
# Inputs:    r0 = e (public exponent),  r1 = phi(n) (totient)
# Output:    r0 = d (private exponent),  or 0 if not found
#---------------------------------------
cprivexp:
    # Push stack 24
    SUB  sp, sp, #24
    STR  lr, [sp]
    STR  r4, [sp, #4]
    STR  r5, [sp, #8]
    STR  r6, [sp, #12]
    STR  r7, [sp, #16]
    STR  r8, [sp, #20]

    MOV  r4, r0             @ r4 = e
    MOV  r5, r1             @ r5 = phi(n)
    MOV  r6, #1             @ r6 = x = 1
    MOV  r8, #1000          @ r8 = iteration limit

cprivexp_loop:
    MUL  r7, r6, r5         @ r7 = x * phi(n)
    ADD  r7, r7, #1         @ r7 = 1 + x*phi(n)   <-- numerator

    MOV  r0, r7             @ dividend = numerator
    MOV  r1, r4             @ divisor  = e
    BL   mod                @ r0 = numerator mod e

    CMP  r0, #0
    BEQ  cprivexp_found     @ remainder 0  =>  found our d

    ADD  r6, r6, #1         @ x++
    CMP  r6, r8
    BGT  cprivexp_fail
    B    cprivexp_loop

cprivexp_found:
    # Divide numerator (r7) by e (r4) via repeated subtraction
    MOV  r0, r7             @ r0 = numerator
    MOV  r1, r4             @ r1 = e
    MOV  r2, #0             @ r2 = quotient (d)

cprivexp_div_loop:
    CMP  r0, r1
    BLT  cprivexp_div_done
    SUB  r0, r0, r1
    ADD  r2, r2, #1
    B    cprivexp_div_loop

cprivexp_div_done:
    MOV  r0, r2             @ return d

    LDR  lr, [sp]
    LDR  r4, [sp, #4]
    LDR  r5, [sp, #8]
    LDR  r6, [sp, #12]
    LDR  r7, [sp, #16]
    LDR  r8, [sp, #20]
    ADD  sp, sp, #24
    BX   lr

cprivexp_fail:
    MOV  r0, #0
    LDR  lr, [sp]
    LDR  r4, [sp, #4]
    LDR  r5, [sp, #8]
    LDR  r6, [sp, #12]
    LDR  r7, [sp, #16]
    LDR  r8, [sp, #20]
    ADD  sp, sp, #24
    BX   lr

#---------------------------------------
# Function:  modexp
# Purpose:   Computes (base ^ exponent) mod n
#            Square-and-multiply, right-to-left binary method
# Inputs:    r0 = base,  r1 = exponent,  r2 = n (modulus)
# Output:    r0 = result
# Notes:     Calls mod via BL multiple times.
#            All working values are in callee-saved registers
#            so BL mod never disturbs them.
#---------------------------------------
modexp:
    # Push stack 24
    SUB  sp, sp, #24
    STR  lr, [sp]
    STR  r4, [sp, #4]
    STR  r5, [sp, #8]
    STR  r6, [sp, #12]
    STR  r7, [sp, #16]
    STR  r8, [sp, #20]

    MOV  r4, r0             @ r4 = base
    MOV  r5, r1             @ r5 = exponent
    MOV  r6, r2             @ r6 = n
    MOV  r7, #1             @ r7 = result = 1

    @ Reduce base mod n before the loop
    MOV  r0, r4
    MOV  r1, r6
    BL   mod
    MOV  r4, r0             @ r4 = base mod n

modexp_loop:
    CMP  r5, #0
    BEQ  modexp_done

    @ If exponent is odd: result = (result * base) mod n
    AND  r8, r5, #1
    CMP  r8, #1
    BNE  modexp_skip_mult

    MUL  r0, r7, r4         @ r0 = result * base
    MOV  r1, r6
    BL   mod
    MOV  r7, r0             @ r7 = (result * base) mod n

modexp_skip_mult:
    @ base = (base * base) mod n
    MUL  r0, r4, r4         @ r0 = base * base
    MOV  r1, r6
    BL   mod
    MOV  r4, r0             @ r4 = base^2 mod n

    LSR  r5, r5, #1         @ exp >>= 1
    B    modexp_loop

modexp_done:
    MOV  r0, r7             @ return result

    LDR  lr, [sp]
    LDR  r4, [sp, #4]
    LDR  r5, [sp, #8]
    LDR  r6, [sp, #12]
    LDR  r7, [sp, #16]
    LDR  r8, [sp, #20]
    ADD  sp, sp, #24
    BX   lr

#---------------------------------------
# Function:  rsa_encrypt
# Purpose:   Encrypts one plaintext character:  c = m^e mod n
# Inputs:    r0 = m (ASCII value),  r1 = e,  r2 = n
# Output:    r0 = ciphertext integer
#---------------------------------------
rsa_encrypt:
    # Push stack 4
    SUB  sp, sp, #4
    STR  lr, [sp]

    BL   modexp             @ r0 = m^e mod n

    LDR  lr, [sp]
    ADD  sp, sp, #4
    BX   lr

#---------------------------------------
# Function:  rsa_decrypt
# Purpose:   Decrypts one ciphertext integer:  m = c^d mod n
# Inputs:    r0 = c (ciphertext),  r1 = d,  r2 = n
# Output:    r0 = plaintext integer (original ASCII value)
#---------------------------------------

rsa_decrypt:
    # Push stack 4
    SUB  sp, sp, #4
    STR  lr, [sp]

    BL   modexp             @ r0 = c^d mod n

    LDR  lr, [sp]
    ADD  sp, sp, #4
    BX   lr

@ end of rsa_lib.s