#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Host check, secure mirror image of the vulnerable one. */
int main(int argc, char **argv) {
    unsigned char session_token[32];
    FILE *source;

    (void)argc;
    (void)argv;

    /* Fixed argument vector, no shell and no caller input. */
    system("date");

    /* The session identifier comes from the kernel CSPRNG. */
    source = fopen("/dev/urandom", "rb");
    if (source == NULL) {
        return 1;
    }
    if (fread(session_token, 1, sizeof(session_token), source) != sizeof(session_token)) {
        fclose(source);
        return 1;
    }
    fclose(source);
    printf("session bytes %u\n", (unsigned)session_token[0]);
    return 0;
}
