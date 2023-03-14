CC = gcc
CFLAGS = -Wall -Wextra -O3
LIBS = -lssl -lcrypto -lm

bruteforce: main.c bruteforce.c
	@$(CC) main.c bruteforce.c $(CFLAGS) -o bruteforce $(LIBS)

clean:
	@$(RM) bruteforce
