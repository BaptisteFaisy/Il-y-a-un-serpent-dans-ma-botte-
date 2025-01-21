#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>

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

void write_stub(int fd, Elf64_Addr entry_point, char *key) {
    unsigned char stub[] = {
        // Assembly stub pour décryptage
        0x48, 0x83, 0xEC, 0x20,             // sub    rsp,0x20
        0x48, 0xB8,                         // movabs rax,<entry_point>
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x44, 0x24, 0x18,       // mov    QWORD PTR [rsp+0x18],rax
        0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00, // lea    rsi,[rip+0x0]
        0xBA, 0x0D, 0x00, 0x00, 0x00,       // mov    edx,0xd
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // mov    rax,0x1
        0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00, // mov    rdi,0x1
        0x0F, 0x05,                         // syscall 
        // ... (code de décryptage)
    };
    
    memcpy(&stub[6], &entry_point, sizeof(entry_point));
    write(fd, stub, STUB_SIZE);
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

    // Trouver la section .text
    Elf64_Shdr *shdr = (Elf64_Shdr *)(data + ehdr->e_shoff);
    char *shstrtab = (char *)(data + shdr[ehdr->e_shstrndx].sh_offset);
    
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (strcmp(&shstrtab[shdr[i].sh_name], ".text") == 0) {
            encrypt_section(data + shdr[i].sh_offset, shdr[i].sh_size, key);
            break;
        }
    }

    // Créer le nouveau fichier
    int out_fd = open("woody", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    write(out_fd, data, st.st_size);
    write_stub(out_fd, ehdr->e_entry, key);
    
    // Modifier l'entête ELF
    lseek(out_fd, 0, SEEK_SET);
    ehdr->e_entry = st.st_size; // Nouveau point d'entrée
    write(out_fd, ehdr, sizeof(Elf64_Ehdr));

    close(fd);
    close(out_fd);
    munmap(data, st.st_size);
    return 0;
}