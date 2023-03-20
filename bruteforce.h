#ifndef BRUTEFORCE_H
#define BRUTEFORCE_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <math.h>
#include <openssl/md5.h>
#include <dirent.h>

#define CC                       "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.!-@*_$#/,+%&?;=~^)[\\]`(<'>|\"" // J'ai enlevé le :
#define CCLEN                    91 // 92 si on met :
#define CPR(str1, str2)          !strcmp((str1), (str2))
#define DICT_NUMBER              1
#define FIFO_NAME                "/tmp/killfifo"

// Fonctions de bruteforce
void md5Force(int startIndex, int nb_proc, unsigned char hash[]);
void blowFishForce();
void eksBlowFishForce();
void SHA256Force();
void SHA512Force();

// Attaque par dictionnaire
void dictionaryAttack(char *hash);

// Fonction qui tue tous les fork
void killFork();

#endif // BRUTEFORCE_H
