#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXLINE 1024

/* utilities */
void show_usage(const char *name);
void unix_error(const char *msg);
void app_error(const char *msg);
char *readline(const char *prompt, char *buf, int size, FILE *stream);

int main(int argc, char *argv[]) {
    if (argc != 2)
        show_usage(argv[0]);
    
    int pid = atoi(argv[1]);
    printf("pid: %d\n", pid);

    char line[MAXLINE];
    while (readline("(memheck) ", line, MAXLINE, stdin) != NULL) {
        printf("%s\n", line);
    }
    

    return 0;
}

void show_usage(const char *name) {
    printf("Usage: %s PID\n", name);
    exit(1);
}

void unix_error(const char *msg) {
    perror(msg);
    exit(1);
}

void app_error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

char *readline(const char *prompt, char *buf, int size, FILE *stream) {
    char *ret_val, *find;

    printf("%s", prompt);
    if (((ret_val = fgets(buf, size, stream)) == NULL) && ferror(stream))
        app_error("readline error");

    if (ret_val) {
        find = strchr(buf, '\n');
        if (find)
            *find = '\0';
        else 
            while (getchar() != '\n')
                continue;
    }

    return ret_val;
}
