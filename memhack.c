#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXLINE 1024

/* utilities */
void show_usage(const char *name);
void unix_error(const char *msg);
void app_error(const char *msg);
char *readline(const char *prompt, char *buf, int size, FILE *stream);

/* cmd */
int cmd_pause();
int cmd_resume();
int cmd_lookup();
int cmd_setup();
int cmd_exit();

struct {
    const char *name;
    int (*handler)();
} cmd_table [] = {
    { "pause", cmd_pause },
    { "resume", cmd_resume },
    { "lookup", cmd_lookup },
	{ "setup", cmd_setup },
	{ "exit", cmd_exit },
};

#define NR_CMD (sizeof(cmd_table) / sizeof(cmd_table[0]))

/* main */
int main(int argc, char *argv[]) {
    if (argc != 2)
        show_usage(argv[0]);
    
    int pid = atoi(argv[1]);
    printf("pid: %d\n", pid);

    char line[MAXLINE];
    while (readline("(memheck) ", line, MAXLINE, stdin) != NULL) {
        char *cmd = strtok(line, " ");
        if (cmd == NULL)
            continue;
        
        for (int i = 0; i < NR_CMD; ++i) {
            if (strcmp(cmd, cmd_table[i].name) == 0) {
                if (cmd_table[i].handler() < 0)
                    return 0;
                break;
            }
        }
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

int cmd_pause() {
    printf("pause: executed");
    return 0;
}

int cmd_resume() {
    printf("resume: executed");
    return 0;
}

int cmd_lookup() {
    printf("lookup: executed");
    return 0;
}

int cmd_setup() {
    printf("setup: executed");
    return 0;
}

int cmd_exit() {
    printf("exit: executed");
    return -1;
}
