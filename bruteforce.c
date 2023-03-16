#include "bruteforce.h"

/* TODO :
 * Ecrire les hash produits dans un fichier au format : hashType_nbChar.txt (à l'intérieur : mdpClair:mdpHashé)
 * Un processus lit un fichier. Il faut donc trouver le nombre de fichiers de mdp pour créer un fork pour chacun (en plus de ceux qui bruteforce)
 * Si tous les mdp de N caractères ont été écrits dans le fichier, ça ne sert plus à rien de les recréer à chaque fois
 * Donner un pattern (comme hashcat) sur la forme des mdp à générer et leur longueur
*/

void killFork() {
  int fifo_fd = open(FIFO_NAME, O_RDONLY);
  char buf[16];

  while (read(fifo_fd, buf, sizeof(buf))> 0) {
    // Kill process with PID from FIFO 
    kill(atoi(buf), SIGTERM);
  }

  close(fifo_fd);
}

void dictionaryAttack(char *hash) {
  // On compte le nombre de fichiers de hash
  DIR *dirp;
  struct dirent *entry;
  char *files[DICT_NUMBER] = { NULL };

  dirp = opendir("./wordlists");
  int i = 0;
  while ((entry = readdir(dirp)) != NULL && i < DICT_NUMBER) {
    if (entry->d_type == DT_REG) {
      char filename[1024] = {0};
      sprintf(filename, "./wordlists/%s", entry->d_name);
      files[i] = strdup(filename); // Alloue dynamiquement la mémoire nécessaire pour copier le nom du fichier trouvé
      i++;
    }
  }

  closedir(dirp);

  // On fait un fork par fichier
  int id;
  FILE *f;
  for (i = 0; i < DICT_NUMBER; i++) {
    id = fork();
    
    // Le fils ouvre le fichier
    if (!id) {
      f = fopen(files[i], "r");
      if (f == NULL) {
           perror("Ouverture du fichier");
           return;
      }
    }
  }
  
  // Le fils lit le fichier ligne par lignes
  if (!id) {
    char line = [1024];
    char *pass, *passHash;
    
    while (fgets(line, sizeof(line), f)) != NULL) {
      // Format de la ligne : mdp:hash
      // On split donc sur le :
      pass = line; // mdp
      passHash = strchr(line, ':'); // son hash
      if (passHash == NULL)
          continue;
      
      *passHash = '\0';
      passHash++;
      passHash[strcspn(passHash, "\n")] = '\0'; // on enlève le \n de la fin

      printf("Comparaison entre %s et %s : %d\n", hash, passHash, memcmp(hash, passHash, strlen(hash)));
      if (memcmp(hash, passHash, strlen(hash)) == 0) {
        puts("----");
        printf("MDP trouvé : %s\n", pass);
        puts("----");

        killFork();

        return;
      }
    }

    fclose(f);
    puts("Dictionary attack finished");
  }
}

void md5Force(int startIndex, int nb_proc, unsigned char hash[]) {
  char pass[32] = {0};

  for(unsigned long long i = startIndex;; i+=nb_proc) {
    int j = 0;

    do {
      pass[j] = CC[((int) (i / pow(CCLEN,j))) % CCLEN];
      ++j;
    } while (j <= log(i) / log(CCLEN));

    printf("%s\n", pass);
    pause();

    unsigned char res[MD5_DIGEST_LENGTH];
    MD5(pass, strlen(pass), res);

    if (!memcmp(hash, res, sizeof(hash))) {
      puts("----");
      printf("MDP trouvé : %s\n", pass);
      puts("----");

      killFork();

      return;
    }
  }
}
