section .text
global _start

_start:
    ; Afficher le message "....WOODY....."
    mov rax, 1          ; sys_write
    mov rdi, 1          ; stdout
    lea rsi, [rel msg]  ; adresse du message
    mov rdx, 13         ; longueur du message
    syscall

    ; Décrypter la section .text
    mov rcx, [rel encrypted_size] ; Taille à décrypter
    lea rsi, [rel encrypted_start] ; Adresse de départ
    lea rdi, [rel key]            ; Clé de chiffrement
decrypt_loop:
    mov al, [rsi]       ; Lire un octet chiffré
    mov rbx, rcx        ; Copier rcx dans rbx
    and rbx, 0xF        ; Calculer rbx = rcx % 16
    xor al, [rdi + rbx] ; Déchiffrer avec la clé
    mov [rsi], al       ; Écrire l'octet déchiffré
    inc rsi             ; Octet suivant
    loop decrypt_loop   ; Répéter pour tous les octets

    ; Retour au programme original
    mov rax, [rel original_entry] ; Charger l'adresse originale dans rax
    jmp rax             ; Saut vers l'entry point original

msg db "...WOODY...", 0xA ; Message à afficher
key times 16 db 0         ; Clé de 16 octets
encrypted_start dq 0      ; Adresse de .text chiffrée
encrypted_size dq 0       ; Taille de .text chiffrée
original_entry dq 0       ; Entry point original (avant chiffrement)