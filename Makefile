NAME = woody_woodpacker
CC = gcc
FLAGS = -Wall -Wextra -Werror -g3
SRCS = woody_woodpacker.c
OBJS = $(SRCS:c=o)
RM = woody stub stub.bin stub.o sample woody_woodpacker.o
all: $(NAME)

$(NAME): $(OBJS)
	$(CC) ./resources/sample.c $(FLAGS)  -m64 -o sample
	$(CC) $(OBJS) $(FLAGS) -o $(NAME)

clean :
	rm -rf $(NAME) $(RM)

fclean :
	rm -rf $(NAME)
re: clean all



	# nasm -f elf64 stub.asm -o stub.o
	# ld -o stub stub.o
	# objcopy -O binary --only-section=.text stub stub.bin