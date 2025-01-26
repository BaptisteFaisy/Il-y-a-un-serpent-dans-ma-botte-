#include "def.h"
#include <sys/mman.h>

#define KEY_SIZE 16
#define STUB_SIZE 512

void generate_key(char *key) {
    int fd = open("/dev/urandom", O_RDONLY);
    read(fd, key, KEY_SIZE);
    close(fd);
}

void encrypt_section(void *data, size_t size, char *key) {
    for (size_t i = 0; i < size; i++) {
        ((char*)data)[i] ^= key[i % KEY_SIZE];
    }
}

void write_stub(int fd, Elf64_Addr entry_point, char *key, Elf64_Addr text_start, size_t text_size, Elf64_Addr stub_vaddr) {
    unsigned char stub[] = {
        // Calcul de l'adresse de base
        0x48, 0x8B, 0x05, 0x16, 0x00, 0x00, 0x00, // mov rax, [rip + 0x16] (stub_vaddr)
        0x48, 0x89, 0xE3,                         // mov rbx, rsp
        0x48, 0x83, 0xE3, 0xF0,                   // and rbx, -16
        0x48, 0x8B, 0x2C, 0x24,                   // mov rbp, [rsp]
        0x48, 0x29, 0xC5,                         // sub rbp, rax

        // Afficher "....WOODY.....\n"
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // sys_write
        0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00, // stdout
        0x48, 0x8D, 0x35, 0x3A, 0x00, 0x00, 0x00, // lea rsi, [rip + 0x3A] (msg)
        0x48, 0xC7, 0xC2, 0x0E, 0x00, 0x00, 0x00, // length 14
        0x0F, 0x05,                               // syscall

        // Décrypter .text
        0x48, 0x31, 0xC9,                         // xor rcx, rcx
        0x48, 0x8D, 0x3D, 0x18, 0x00, 0x00, 0x00, // lea rdi, [rip + 0x18] (key)
        0x48, 0x8D, 0x35, 0xE7, 0xFF, 0xFF, 0xFF, // lea rsi, [rip - 0x19] (text_start)
        0x48, 0x01, 0xEE,                         // add rsi, rbp
        0x48, 0x8B, 0x15, 0x00, 0x00, 0x00, 0x00, // mov rdx, [rip] (text_size)
        0x48, 0x8A, 0x04, 0x0F,                   // mov al, [rdi + rcx]
        0x30, 0x04, 0x0E,                         // xor [rsi + rcx], al
        0x48, 0xFF, 0xC1,                         // inc rcx
        0x48, 0x39, 0xD1,                         // cmp rcx, rdx
        0x72, 0xF4,                               // jb -12

        // Sauter vers entry_point
        0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00, // mov rax, [rip + 0x10] (entry_point)
        0x48, 0x01, 0xE8,                         // add rax, rbp
        0xFF, 0xE0,                               // jmp rax

        // Données
        '.', '.', '.', '.', 'W', 'O', 'O', 'D', 'Y', '.', '.', '.', '.', '\n', // msg (offset 0x3A)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // stub_vaddr (offset 0x16)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // text_start (offset 0x1E)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // text_size (offset 0x26)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // key (offset 0x2E)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // entry_point (offset 0x36)
    };

    // Remplissage des données
    memcpy(&stub[0x16], &stub_vaddr, sizeof(Elf64_Addr));
    memcpy(&stub[0x1E], &text_start, sizeof(Elf64_Addr));
    memcpy(&stub[0x26], &text_size, sizeof(size_t));
    memcpy(&stub[0x2E], key, KEY_SIZE);
    memcpy(&stub[0x36], &entry_point, sizeof(Elf64_Addr));

    write(fd, stub, sizeof(stub));
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <binary>\n", argv[0]);
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);
    struct stat st;
    fstat(fd, &st);
    
    void *data = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;
    
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
        fprintf(stderr, "Not an ELF file\n");
        return 1;
    }

    char key[KEY_SIZE];
    generate_key(key);
    printf("key_value: ");
    for (int i = 0; i < KEY_SIZE; i++) printf("%02X", (unsigned char)key[i]);
    printf("\n");
    Elf64_Shdr *shdr = (Elf64_Shdr *)(data + ehdr->e_shoff);
    char *shstrtab = (char *)(data + shdr[ehdr->e_shstrndx].sh_offset);
    
    Elf64_Addr text_start = 0;
    size_t text_size = 0;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (strcmp(&shstrtab[shdr[i].sh_name], ".text") == 0) {
            text_start = shdr[i].sh_addr;    // Adresse virtuelle de .text
            text_size = shdr[i].sh_size;     // Taille de .text
            encrypt_section(data + shdr[i].sh_offset, text_size, key); // Chiffrer
            break;
        }
    }

    // Trouver le segment exécutable et calculer l'adresse du stub
    Elf64_Phdr *phdr = (Elf64_Phdr *)(data + ehdr->e_phoff);
    Elf64_Addr stub_vaddr = 0;
    off_t stub_offset = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) {
            stub_offset = phdr[i].p_offset + phdr[i].p_filesz;
            stub_vaddr = phdr[i].p_vaddr + phdr[i].p_filesz;
            phdr[i].p_filesz += STUB_SIZE;
            phdr[i].p_memsz += STUB_SIZE;
            break;
        }
    }

    ehdr->e_entry = stub_vaddr;

    // Écrire le fichier modifié
    int out_fd = open("woody", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    write(out_fd, ehdr, sizeof(Elf64_Ehdr)); // <-- Ajoutez cette ligne

    // Puis écrire le reste du contenu original
    lseek(out_fd, sizeof(Elf64_Ehdr), SEEK_SET); // Sauter l'en-tête déjà écrit
    write(out_fd, data + sizeof(Elf64_Ehdr), st.st_size - sizeof(Elf64_Ehdr));
    lseek(out_fd, stub_offset, SEEK_SET);
    write_stub(out_fd, ehdr->e_entry, key, text_start, text_size, stub_vaddr);


    close(fd);
    close(out_fd);
    munmap(data, st.st_size);
    return 0;
}