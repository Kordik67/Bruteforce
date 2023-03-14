#include "bruteforce.h"

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage : %s 'hash'\n", argv[0]);
    return -1;
  }

  system("rm -f /tmp/killfifo");
  int fifo_fd;
  char buf[16];

  if (mkfifo(FIFO_NAME, 0666) < 0) {
    printf("Error creating FIFO\n");
    exit(1);
  }

  clock_t begin = clock();

  char hashType[5] = {0};
  strncpy(hashType, argv[1], argv[1][3] == '$' ? 4 : 3);

  /*printf("Hashage : %s\n", CPR(hashType, "$1$") ? "MD5" :
                             CPR(hashType, "$2$") ? "Blowfish" :
                             CPR(hashType, "$2a$") ? "eksblowfish" :
                             CPR(hashType, "$5$") ? "SHA-256" :
                             CPR(hashType, "$6$") ? "SHA-512" : "Inconnu");*/

  int start = argv[1][3] == '$' ? 4 : 3;
  unsigned char hash[MD5_DIGEST_LENGTH] = {0};

  for (int i = 0; i < MD5_DIGEST_LENGTH; i += 4) {
    sscanf(argv[1] + start + (i << 1), "%02hhx", hash + i);
    sscanf(argv[1] + start + ((i + 1) << 1), "%02hhx", hash + (i + 1));
    sscanf(argv[1] + start + ((i + 2) << 1), "%02hhx", hash + (i + 2));
    sscanf(argv[1] + start + ((i + 3) << 1), "%02hhx", hash + (i + 3));
  }

  //printf("Hash : %s\n", argv[1] + start);

  int fn = 7; // Par défault 2^fn
  int startIndex = CCLEN * CCLEN * CCLEN, id, nb_proc = pow(2, fn);

  int dictFork = fork();
  if (dictFork != 0) {
    //dictionaryAttack(argv[1] + start);
    return 0;
  }

  for (int f = 0; f < fn; ++f) {
    id = fork();

    if (!id) {
      // Open FIFO for writing
      fifo_fd = open(FIFO_NAME, O_WRONLY);

      // Write PID to FIFO
      sprintf(buf, "%d", getpid());
      write(fifo_fd, buf, strlen(buf));
      close(fifo_fd);

      startIndex += 0;
      continue;
    }
    startIndex += pow(2, f);
  }

  if (CPR(hashType, "$1$"))
    md5Force(startIndex, nb_proc, hash);
  /*else if (CPR(hashType, "$2$"))
    blowFishForce();
  else if (CPR(hashType, "$2a$"))
    eksBlowFishForce();
  else if (CPR(hashType, "$5$"))
    SHA256Force();
  else
    SHA512Force();*/

  // Remove FIFO
  unlink(FIFO_NAME);

  clock_t end = clock();
  printf("%lf secondes écoulées\n", (double)(end - begin) * 0.000001); // Au lieu de diviser par CLOCKS_PER_SECOND
  
  return 0;
}
