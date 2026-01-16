// vuln.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void run_cmd(char *user) {
    char cmd[256];
    // 命令注入
    sprintf(cmd, "ping %s", user);
    system(cmd);
}

void read_file(char *name) {
    char path[256];
    // 路径穿越
    sprintf(path, "/safe/dir/%s", name);
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}

int main(int argc, char *argv[]) {
    char buf[0x10];
    gets(buf);
    if (argc > 1) {
        run_cmd(buf);
        read_file(buf);
    }
    return 0;
}
