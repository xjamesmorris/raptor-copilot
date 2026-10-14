#define _POSIX_C_SOURCE 200809L

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested = 0;

static void handle_stop(int signum)
{
    (void)signum;
    stop_requested = 1;
}

int main(void)
{
    const char *home = getenv("HOME");
    char marker[4096];
    FILE *stream;

    if (home == NULL) {
        return 2;
    }
    if (snprintf(marker, sizeof(marker), "%s/native-frontend-ready", home)
            >= (int)sizeof(marker)) {
        return 3;
    }
    if (signal(SIGTERM, handle_stop) == SIG_ERR
            || signal(SIGINT, handle_stop) == SIG_ERR) {
        return 4;
    }
    stream = fopen(marker, "w");
    if (stream == NULL) {
        return 5;
    }
    if (fprintf(stream, "%ld\n", (long)getpid()) < 0
            || fclose(stream) != 0) {
        return 6;
    }
    while (!stop_requested) {
        pause();
    }
    return 0;
}
