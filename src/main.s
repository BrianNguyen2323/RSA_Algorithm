.text
.global main

@ ---- libc functions ----
.extern printf
.extern scanf
.extern fopen
.extern fclose
.extern fprintf
.extern fscanf
.extern fputc
.extern fgets
.extern getchar
.extern stdin                @ FILE* stdin from libc

@ ---- rsa_lib.s functions ----
.extern primeCheck
.extern calcTotient
.extern cpubexp
.extern cprivexp
.extern rsa_encrypt
.extern rsa_decrypt

main:
    # Push stack 32 — save lr + r4-r9 (7 words; pad to 8 for 8-byte align)
    SUB  sp, sp, #32
    STR  lr, [sp]
    STR  r4, [sp, #4]
    STR  r5, [sp, #8]
    STR  r6, [sp, #12]
    STR  r7, [sp, #16]
    STR  r8, [sp, #20]
    STR  r9, [sp, #24]

@ --------------------------------------------------------
@ STEP 1: Read and validate p
@ --------------------------------------------------------
get_p:
    LDR  r0, =prompt_p
    BL   printf

    LDR  r0, =fmt_d
    LDR  r1, =var_p
    BL   scanf

    LDR  r1, =var_p
    LDR  r0, [r1]           @ r0 = p

    @ Range check: 2 <= p < 50
    CMP  r0, #2
    BLT  bad_p
    CMP  r0, #50
    BGE  bad_p

    @ Prime check
    BL   primeCheck         @ r0 = 1 if prime, 0 if not
    CMP  r0, #0
    BEQ  bad_p
    B    get_q

bad_p:
    LDR  r0, =msg_not_prime
    BL   printf
    B    get_p

@ --------------------------------------------------------
@ STEP 2: Read and validate q (must differ from p)
@ --------------------------------------------------------
get_q:
    LDR  r0, =prompt_q
    BL   printf

    LDR  r0, =fmt_d
    LDR  r1, =var_q
    BL   scanf

    LDR  r1, =var_q
    LDR  r0, [r1]           @ r0 = q

    @ Range check
    CMP  r0, #2
    BLT  bad_q
    CMP  r0, #50
    BGE  bad_q

    @ q must not equal p
    LDR  r1, =var_p
    LDR  r1, [r1]
    CMP  r0, r1
    BEQ  bad_q_same

    BL   primeCheck         @ r0 = 1 if prime
    CMP  r0, #0
    BEQ  bad_q
    B    compute_keys

bad_q:
    LDR  r0, =msg_not_prime
    BL   printf
    B    get_q

bad_q_same:
    LDR  r0, =msg_same_pq
    BL   printf
    B    get_q

@ --------------------------------------------------------
@ STEP 3: Compute n = p*q  and  phi = (p-1)(q-1)
@ --------------------------------------------------------
compute_keys:
    @ n = p * q
    LDR  r0, =var_p
    LDR  r0, [r0]
    LDR  r1, =var_q
    LDR  r1, [r1]
    MUL  r2, r0, r1
    LDR  r3, =var_n
    STR  r2, [r3]

    @ phi = calcTotient(p, q)
    LDR  r0, =var_p
    LDR  r0, [r0]           @ r0 = p
    LDR  r1, =var_q
    LDR  r1, [r1]           @ r1 = q
    BL   calcTotient        @ r0 = phi
    LDR  r1, =var_phi
    STR  r0, [r1]

@ --------------------------------------------------------
@ STEP 4: Read and validate e
@ --------------------------------------------------------
get_e:
    @ Show phi so user knows the valid range
    LDR  r0, =msg_phi
    LDR  r1, =var_phi
    LDR  r1, [r1]
    BL   printf

    LDR  r0, =prompt_e
    BL   printf

    LDR  r0, =fmt_d
    LDR  r1, =var_e
    BL   scanf

    LDR  r0, =var_e
    LDR  r0, [r0]           @ r0 = e
    LDR  r1, =var_phi
    LDR  r1, [r1]           @ r1 = phi
    BL   cpubexp            @ r0 = 1 valid, 0 invalid
    CMP  r0, #0
    BEQ  bad_e
    B    compute_d

bad_e:
    LDR  r0, =msg_bad_e
    BL   printf
    B    get_e

@ --------------------------------------------------------
@ STEP 5: Compute d via cprivexp(e, phi)
@ --------------------------------------------------------
compute_d:
    LDR  r0, =var_e
    LDR  r0, [r0]
    LDR  r1, =var_phi
    LDR  r1, [r1]
    BL   cprivexp           @ r0 = d
    LDR  r1, =var_d
    STR  r0, [r1]

@ --------------------------------------------------------
@ STEP 6: Print public and private keys
@ --------------------------------------------------------
    LDR  r0, =msg_pubkey
    LDR  r1, =var_e
    LDR  r1, [r1]
    LDR  r2, =var_n
    LDR  r2, [r2]
    BL   printf

    LDR  r0, =msg_privkey
    LDR  r1, =var_d
    LDR  r1, [r1]
    LDR  r2, =var_n
    LDR  r2, [r2]
    BL   printf

@ --------------------------------------------------------
@ STEP 7: Prompt for plaintext message
@ Use fgets() so spaces in the message are kept.
@ scanf("%s") would stop at the first whitespace.
@ --------------------------------------------------------
    LDR  r0, =prompt_msg
    BL   printf

    @ Consume the leftover newline left in stdin from the previous
    @ scanf("%d") call. Without this, fgets() would return an empty
    @ first line.
    BL   getchar

    @ fgets(msg_buf, 256, stdin)
    LDR  r0, =msg_buf       @ buffer
    MOV  r1, #256           @ size
    LDR  r2, =stdin         @ FILE** stdin (extern symbol — pointer to FILE*)
    LDR  r2, [r2]           @ dereference: r2 = stdin (the actual FILE*)
    BL   fgets

    @ Strip trailing newline from msg_buf if present.
    @ Walk to end of string, then if the last char before NUL is '\n', NUL it.
    LDR  r0, =msg_buf
strip_nl_loop:
    LDRB r1, [r0]
    CMP  r1, #0
    BEQ  strip_nl_check     @ reached NUL — back up and check
    ADD  r0, r0, #1
    B    strip_nl_loop
strip_nl_check:
    @ r0 currently points at the NUL byte. Step back one and check for \n.
    LDR  r2, =msg_buf
    CMP  r0, r2
    BEQ  strip_nl_done      @ empty string — nothing to strip
    SUB  r0, r0, #1
    LDRB r1, [r0]
    CMP  r1, #10            @ '\n'
    BNE  strip_nl_done
    MOV  r1, #0
    STRB r1, [r0]           @ overwrite \n with NUL
strip_nl_done:

@ --------------------------------------------------------
@ STEP 8: Encrypt char-by-char, write ints to encrypted.txt
@
@ Register usage during the loop (all callee-saved):
@   r4 = FILE* fp        (output stream)
@   r5 = e               (public exponent)
@   r6 = n               (modulus)
@   r7 = pointer into msg_buf
@ --------------------------------------------------------
    @ Open encrypted.txt for writing
    LDR  r0, =fname_enc
    LDR  r1, =fmode_w
    BL   fopen
    CMP  r0, #0
    BEQ  file_err
    MOV  r4, r0             @ r4 = FILE* (encrypted.txt)

    LDR  r5, =var_e
    LDR  r5, [r5]           @ r5 = e
    LDR  r6, =var_n
    LDR  r6, [r6]           @ r6 = n
    LDR  r7, =msg_buf       @ r7 = pointer into message

encrypt_loop:
    LDRB r0, [r7]           @ r0 = current char
    CMP  r0, #0
    BEQ  encrypt_done       @ null terminator -> done

    @ rsa_encrypt(m=r0, e=r1, n=r2)
    MOV  r1, r5             @ e
    MOV  r2, r6             @ n
    BL   rsa_encrypt        @ r0 = ciphertext integer

    @ fprintf(fp, "%d ", ciphertext)
    MOV  r2, r0             @ ciphertext -> 3rd arg of fprintf
    LDR  r1, =fmt_enc       @ format string -> 2nd arg
    MOV  r0, r4             @ FILE* -> 1st arg
    BL   fprintf

    ADD  r7, r7, #1         @ advance to next character
    B    encrypt_loop

encrypt_done:
    @ Close encrypted.txt
    MOV  r0, r4
    BL   fclose

    LDR  r0, =msg_encrypted
    BL   printf

@ --------------------------------------------------------
@ STEP 9: Print encrypted.txt contents to terminal
@         (Re-open and stream the file via fscanf "%d")
@ --------------------------------------------------------
    LDR  r0, =msg_showing_enc
    BL   printf

    LDR  r0, =fname_enc
    LDR  r1, =fmode_r
    BL   fopen
    CMP  r0, #0
    BEQ  file_err
    MOV  r4, r0             @ r4 = FILE* (encrypted.txt for reading)

print_enc_loop:
    @ fscanf(fp, "%d", &var_tmp)
    MOV  r0, r4
    LDR  r1, =fmt_d
    LDR  r2, =var_tmp
    BL   fscanf
    CMP  r0, #1             @ fscanf returns count of matched items
    BNE  print_enc_done

    @ printf("%d ", var_tmp)
    LDR  r0, =fmt_print_int
    LDR  r1, =var_tmp
    LDR  r1, [r1]
    BL   printf
    B    print_enc_loop

print_enc_done:
    MOV  r0, r4
    BL   fclose

    LDR  r0, =msg_newline
    BL   printf

@ --------------------------------------------------------
@ STEP 10: Wait for user to press 'd' to decrypt
@ --------------------------------------------------------
wait_d:
    LDR  r0, =prompt_decrypt
    BL   printf

    LDR  r0, =fmt_c_in
    LDR  r1, =var_choice_c
    BL   scanf

    LDR  r1, =var_choice_c
    LDRB r0, [r1]
    CMP  r0, #'d'
    BNE  wait_d             @ anything other than 'd' -> re-prompt

@ --------------------------------------------------------
@ STEP 11: Decrypt encrypted.txt -> plaintext.txt
@
@ Register usage during the loop (all callee-saved):
@   r4 = FILE* fp_in   (encrypted.txt, reading)
@   r5 = d             (private exponent)
@   r6 = n             (modulus)
@   r8 = FILE* fp_out  (plaintext.txt, writing)
@   r9 = decrypted character (saved across BL fputc / printf)
@ --------------------------------------------------------
    @ Open encrypted.txt for reading
    LDR  r0, =fname_enc
    LDR  r1, =fmode_r
    BL   fopen
    CMP  r0, #0
    BEQ  file_err
    MOV  r4, r0             @ r4 = read FILE*

    @ Open plaintext.txt for writing
    LDR  r0, =fname_plain
    LDR  r1, =fmode_w
    BL   fopen
    CMP  r0, #0
    BEQ  file_err
    MOV  r8, r0             @ r8 = write FILE*

    LDR  r5, =var_d
    LDR  r5, [r5]           @ r5 = d
    LDR  r6, =var_n
    LDR  r6, [r6]           @ r6 = n

    LDR  r0, =msg_decrypting
    BL   printf

decrypt_loop:
    @ fscanf(fp_in, "%d", &var_tmp)
    MOV  r0, r4
    LDR  r1, =fmt_d
    LDR  r2, =var_tmp
    BL   fscanf
    CMP  r0, #1
    BNE  decrypt_done       @ EOF or no match -> done

    @ rsa_decrypt(c=r0, d=r1, n=r2)
    LDR  r0, =var_tmp
    LDR  r0, [r0]           @ r0 = ciphertext
    MOV  r1, r5             @ d
    MOV  r2, r6             @ n
    BL   rsa_decrypt        @ r0 = plaintext ASCII value

    MOV  r9, r0             @ save the decrypted character

    @ fputc(c, fp_out)  -- args: int c (r0), FILE* (r1)
    MOV  r0, r9
    MOV  r1, r8
    BL   fputc

    @ printf("%c", c)
    LDR  r0, =fmt_c
    MOV  r1, r9
    BL   printf

    B    decrypt_loop

decrypt_done:
    @ Close both files
    MOV  r0, r4
    BL   fclose
    MOV  r0, r8
    BL   fclose

    LDR  r0, =msg_newline
    BL   printf
    LDR  r0, =msg_done
    BL   printf

@ --------------------------------------------------------
@ STEP 12: Exit cleanly
@ --------------------------------------------------------
exit_main:
    MOV  r0, #0             @ return 0 from main
    LDR  lr, [sp]
    LDR  r4, [sp, #4]
    LDR  r5, [sp, #8]
    LDR  r6, [sp, #12]
    LDR  r7, [sp, #16]
    LDR  r8, [sp, #20]
    LDR  r9, [sp, #24]
    ADD  sp, sp, #32
    BX   lr

file_err:
    LDR  r0, =msg_file_err
    BL   printf
    MOV  r0, #1             @ return 1 (error)
    LDR  lr, [sp]
    LDR  r4, [sp, #4]
    LDR  r5, [sp, #8]
    LDR  r6, [sp, #12]
    LDR  r7, [sp, #16]
    LDR  r8, [sp, #20]
    LDR  r9, [sp, #24]
    ADD  sp, sp, #32
    BX   lr

@ ============================================================
.data

@ --- Prompts ---
prompt_p:        .asciz "Enter prime p (2-50): "
prompt_q:        .asciz "Enter prime q (2-50 -- BUT NOT SAME AS P): "
prompt_e:        .asciz "Enter public exponent e: "
prompt_msg:      .asciz "Enter message to encrypt: "
prompt_decrypt:  .asciz "Check encrypted.txt! -- now press 'd' and enter to decrypt: "

@ --- Status messages ---
msg_phi:         .asciz "  phi(n) = %d  (e must be co-prime to phi, 1 < e < phi)\n"
msg_pubkey:      .asciz "  Public key  (e, n) = (%d, %d)\n"
msg_privkey:     .asciz "  Private key (d, n) = (%d, %d)\n"
msg_encrypted:   .asciz "Message encrypted -> encrypted.txt\n"
msg_showing_enc: .asciz "--- encrypted.txt ---\n"
msg_decrypting:  .asciz "--- decrypted message ---\n"
msg_done:        .asciz "Decrypted message saved to plaintext.txt\n"
msg_newline:     .asciz "\n"

@ --- Error messages ---
msg_not_prime:   .asciz "Not a valid prime in range [2,50). Try again.\n"
msg_same_pq:     .asciz "p and q must be different. Try again.\n"
msg_bad_e:       .asciz "Invalid e (need 1 < e < phi and gcd(e,phi)=1). Try again.\n"
msg_file_err:    .asciz "Error: could not open file.\n"

@ --- Format strings ---
fmt_d:           .asciz "%d"
fmt_str:         .asciz "%255s"
fmt_enc:         .asciz "%d "
fmt_print_int:   .asciz "%d "
fmt_c:           .asciz "%c"
fmt_c_in:        .asciz " %c"

@ --- File names and modes ---
fname_enc:       .asciz "encrypted.txt"
fname_plain:     .asciz "plaintext.txt"
fmode_w:         .asciz "w"
fmode_r:         .asciz "r"

@ ============================================================
.bss

var_p:           .skip 4
var_q:           .skip 4
var_n:           .skip 4
var_phi:         .skip 4
var_e:           .skip 4
var_d:           .skip 4
var_tmp:         .skip 4
var_choice_c:    .skip 4
msg_buf:         .skip 256

@ end of main.s
