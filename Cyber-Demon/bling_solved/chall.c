#include <stdio.h>
#include <unistd.h>
#include <string.h>

int art(void) {
    char *art = "        \
                      \n\
                      |             \n\
                        |           \n\
                   | |              \n\
       ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀|⠀⠀o⠀/⠀|⠀⠀⠀⠀⠀⠀⠀⠀ \n\
      ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀/\\⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ \n\
      ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀/\\⠀⠀⠀⠀⠀⠀⠀⠀⠀ \n\
      ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ \n\
      ⠀⠀⠀⠀⠀⠀⠀⣀⣀⣠⣤⣤⣤⣤⣤⣤⣤⣤⣄⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀ \n\
      ⠀⠀⢀⣤⣴⣾⣿⣿⡿⠿⠿⠿⠟⠛⠛⠻⠿⠿⠿⢿⣿⣿⣷⣦⣤⡀⠀⠀⠀ \n\
      ⢀⣼⣿⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⢿⣿⣧⡀⠀ \n\
      ⢸⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⡇⠀ \n\
      ⠈⢻⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡟⠁⠀ \n\
      ⠀⠀⠈⠛⠳⢦⣤⣄⣀⣀⡀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣠⣤⡴⠞⠛⠁⠀⠀⠀ \n\
      ⠀⠀⠀⠀⠀⠀⠀⠈⠉⠙⠛⠛⠛⠛⠛⠛⠛⠛⠋⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀ \n\
      ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀  \n";
    write(1, art, strlen(art));
}

int vuln(void) {
    char buf[40] = {0};

    read(0, buf, 60);
    printf(buf);
    return 0;
}

void init(void) {
    setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);
    setvbuf(stderr,NULL,_IONBF,0);
}

int main(void) {
    init();
    art();
    while(1) {
        printf(">> ");
        vuln();
        puts("");
    }
}