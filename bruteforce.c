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
    char line[1024]; // Allocation de mémoire de façon statique
    char *pass, *passHash;
    
    while (fgets(line, sizeof(line), f) != NULL) {
      // Format de la ligne : mdp:hash
      // On split donc sur le :
      pass = line; // mdp
      passHash = strchr(line, ':'); // son hash, on extrait la chaine de caractères après le caractère :
      if (passHash == NULL)
          continue;
      
      *passHash = '\0';
      passHash++;
      passHash[strcspn(passHash, "\n")] = '\0'; // on enlève le \n de la fin

      printf("Comparaison entre %s et %s : %d\n", hash, passHash, memcmp(hash, passHash, strlen(hash)));
      if (memcmp(hash, passHash, strlen(hash)) == 0) { // memcmp plus rapide que strcmp
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

unsigned long long intpow(unsigned long long a, unsigned long long b) {
  return b ? a * intpow(a, b-1) : 1;
}

unsigned long long sumpow(unsigned long long a, unsigned long long b) {
  unsigned long long r = 0;

  for (int i = 1; i < n; i++)
    r += intpow(a, i);

  return r;
}

int nbchar(unsigned long long i) {
  int nb = 1;
  while (i > sumpow(CCLEN, nb+1))
    ++nb;

  return nb;
}

// TODO : Peut-être utiliser des threads à la place des fork
void md5Force(int startIndex, int nb_proc, unsigned char hash[]) {
  int nb_char = nbchar(start);
  unsigned long long borne_inf = sum_pow(CCLEN,nb_caracter); // BORNE MINI DE l'INTERVAL
  unsigned long long borne_sup = sum_pow(CCLEN,nb_caracter+1)-1; // BORNE MAXI DE l'INTERVAL
  char pass[MAX_PASSWORD_LEN] = {0};
  
  for(unsigned long long i = start; i < end; i++){
    if(i > borne_sup){
      nb_caracter++;
      borne_inf = sum_pow(CCLEN,nb_caracter);
      borne_sup = sum_pow(CCLEN,nb_caracter+1)-1;
    }
    
    for(int c = 0 ; c < nb_caracter;c++){
      pass[c] = CC[ ( (i-borne_inf)/intpow(CCLEN,c) ) % CCLEN ]; 
    }
    
    printf("[%d ; %d] \n",borne_inf,borne_sup);
    printf("nb_car=%d \n",nb_caracter);
    printf("index du mot = %d --> '%s'\n",i,pass);
    printf("-------\n");

    unsigned char res[MD5_DIGEST_LENGTH];
    MD5((const unsigned char *) pass, nb_caracter, res);
    
    if(memcmp(res,hash2find, MD5_DIGEST_LENGTH)){
      printf("!!!\nPASSWORD FOUND : '%s'\n!!!\n",pass);
      return;
    }
  }
}
