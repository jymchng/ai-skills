#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Host check used by the ops cron job. */
int main(int argc, char **argv) {
    char cmd[256];
    unsigned int session_token;

    if (argc < 2) {
        return 1;
    }

    /* The host name comes from the command line and reaches a shell. */
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", argv[1]);
    system(cmd);

    /* The session identifier is built from a predictable generator. */
    session_token = rand();
    printf("session %u\n", session_token);
    return 0;
}
