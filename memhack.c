#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MAXLINE 1024

/* utilities */
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
struct {
    pid_t pid;
} G;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s PID\n", argv[0]);
        return 1;
    }
    
    G.pid = atoi(argv[1]);

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
    if (ptrace(PTRACE_ATTACH, G.pid, NULL, NULL) == -1)
        unix_error("Ptrace attach error");

    if ((wait(NULL) != G.pid))
        app_error("Wait error");

    printf("Pause: executed\n");
    return 0;
}

int cmd_resume() {
    if (ptrace(PTRACE_DETACH, G.pid, NULL, NULL) == -1)
        unix_error("Ptrace detach error");

    printf("Resume: executed\n");
    return 0;
}

long getdata(void *addr) {
    long data = ptrace(PTRACE_PEEKDATA, G.pid, addr, NULL);
    printf("data %lx\n", data);
    return data;
}

int cmd_lookup() {
    // char *arg = strtok(NULL, " ");
    // if (arg == NULL) {
    //     printf("Usage: lookup <number>\n");
    //     return 0;
    // }
    
    // int number = atoi(arg);


    getdata((void *)0x400614);
    //printf("lookup: %d executed\n", number);
    return 0;
}

int cmd_setup() {
    char *arg = strtok(NULL, " ");
    if (arg == NULL) {
        printf("Usage: setup <number>\n");
        return 0;
    }

    int number = atoi(arg);
    printf("setup: %d executed\n", number);
 
    return 0;
}

int cmd_exit() {
    return -1;
}
