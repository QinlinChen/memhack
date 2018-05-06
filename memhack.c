#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <assert.h>

#define MAXLINE 1024

/* utilities */
void unix_error(const char *msg);
void app_error(const char *msg);
char *readline(const char *prompt, char *buf, int size, FILE *stream);

/* list */
typedef struct _node_t {
    char *addr;
    struct _node_t *prev;
    struct _node_t *next;
} node_t;

typedef struct _list_t {
    node_t NIL;
    int size;
} list_t;

void init_list(list_t *list);
void add_list(list_t *list, char *addr);
void remove_list(list_t *list, node_t *node);
void filter_list(list_t *list, char *addr);
void print_list(list_t *list);

/* ptrace wrapper */
void ptrace_attach(pid_t pid);
void ptrace_detach(pid_t pid);
long ptrace_peekdata(pid_t pid, void *addr);
void ptrace_pokedata(pid_t pid, void *addr, long data);
void ptrace_read(pid_t pid, void *addr, void *buf, size_t size);
void ptrace_write(pid_t pid, void *addr, void *buf, size_t size);

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

/* global */
struct {
    pid_t pid;
    list_t list;
} G;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s PID\n", argv[0]);
        return 1;
    }
    
    // initialize
    G.pid = atoi(argv[1]);
    init_list(&G.list);

    // begin
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

void init_list(list_t *list) {
    list->NIL.addr = NULL;
    list->size = 0;
    list->NIL.next = list->NIL.prev = &list->NIL;
}

void add_list(list_t *list, char *addr) {
    node_t *node = (node_t *)malloc(sizeof(node_t));
    node->addr = addr;
    node->next = list->NIL.next;
    list->NIL.next->prev = node;
    list->NIL.next = node;
    node->prev = &list->NIL;
    list->size += 1;
}

void remove_list(list_t *list, node_t *node) {
    node->prev->next = node->next;
    node->next->prev = node->prev;
    free(node);
    list->size -= 1;
}

void filter_list(list_t *list, char *addr) {
    node_t *scan = list->NIL.next;
    while (scan != &list->NIL) {
        if (scan->addr == addr) {
            scan = scan->prev;
            remove_list(list, scan->next);
        }
        scan = scan->next;
    }
}

void print_list(list_t *list) {
    printf("list size: %d\n", list->size);
    node_t *scan = list->NIL.next;
    while (scan != &list->NIL) {
        assert(scan->next->prev == scan);
        printf("addr: %p\n", scan->addr);
        scan = scan->next;
    }
}

void ptrace_attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
        unix_error("Ptrace attach error");
}

void ptrace_detach(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1)
        unix_error("Ptrace detach error");
}

long ptrace_peekdata(pid_t pid, void *addr) {
    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    if (data == -1 && errno != 0)
        unix_error("Ptrace peekdata error");
    return data;
}

void ptrace_pokedata(pid_t pid, void *addr, long data) {
    if (ptrace(PTRACE_POKEDATA, pid, addr, (void *)data) == -1)
        unix_error("Ptrace pokedata error");
}

void ptrace_read(pid_t pid, void *addr, void *buf, size_t size) {
    assert(size > 0);
    char *src = (char *)addr;
    char *dst = (char *)buf;

    while (size >= sizeof(long)) {
        *(long *)dst = ptrace_peekdata(pid, src);
        size -= sizeof(long);
        dst += sizeof(long);
        src += sizeof(long);
    }

    if (size != 0) {
        long data = ptrace_peekdata(pid, src);
        memcpy(dst, &data, size);
    }
}

void ptrace_write(pid_t pid, void *addr, void *buf, size_t size) {
    assert(size > 0);
    char *src = (char *)buf;
    char *dst = (char *)addr;

    while (size >= sizeof(long)) {
        ptrace_pokedata(pid, dst, *(long *)src);
        size -= sizeof(long);
        dst += sizeof(long);
        src += sizeof(long);
    }

    if (size != 0) {
        long data = ptrace_peekdata(pid, dst);
        printf("before data: %lx, size: %d", size);
        memcpy(&data, src, size);
        printf("after data: %lx, size: %d", size);
        ptrace_pokedata(pid, dst, data);
    }
}

int cmd_pause() {
    ptrace_attach(G.pid);

    if ((wait(NULL) != G.pid))
        app_error("Wait error");

    printf("Success\n");
    return 0;
}

int cmd_resume() {
    ptrace_detach(G.pid);

    printf("Success\n");
    return 0;
}

int cmd_exit() {
    return -1;
}

int cmd_lookup() {
    // char *arg = strtok(NULL, " ");
    // if (arg == NULL) {
    //     printf("Usage: lookup <number>\n");
    //     return 0;
    // }
    // long number = atol(arg);
    char buf[1024];
    ptrace_read(G.pid, (void *)0x601044, buf, 16);
    for (int i = 0; i < 16; ++i) {
        printf("%.2x ", buf[i]);
    }
    printf("\n");

    // printf("%ld\n", ptrace_peekdata(G.pid, (void *)0x601044));
    
    //printf("lookup: %ld executed\n", number);
    return 0;
}

int cmd_setup() {
    char *arg = strtok(NULL, " ");
    if (arg == NULL) {
        printf("Usage: setup <number>\n");
        return 0;
    }

    long number = atol(arg);
    long size = atol(strtok(NULL, " "));

    printf("number %ld, size %ld\n", number, size);
    ptrace_write(G.pid, (void *)0x601044, &number, size);
    ptrace_pokedata(G.pid, (void *)0x601044, number);
    
    char buf[1024];
    ptrace_read(G.pid, (void *)0x601044, buf, 16);
    for (int i = 0; i < 16; ++i) {
        printf("%.2x ", buf[i]);
    }
    printf("\n");

    printf("Success\n");
    return 0;
}
