#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *selected_model(int argc, char **argv)
{
    int index;

    for (index = 1; index < argc; index++) {
        if (strcmp(argv[index], "--model") == 0) {
            return index + 1 < argc ? argv[index + 1] : NULL;
        }
        if (strncmp(argv[index], "--model=", 8) == 0) {
            return argv[index] + 8;
        }
    }
    return NULL;
}

static int write_capture(int argc, char **argv)
{
    const char *capture = getenv("RAPTOR_TEST_FRONTEND_CAPTURE");
    const char *frontend_model;
    char cwd[4096];
    FILE *stream;
    int index;

    if (capture == NULL) {
        return 0;
    }
    stream = fopen(capture, "w");
    if (stream == NULL) {
        return 10;
    }
    if (getcwd(cwd, sizeof(cwd)) == NULL
            || fprintf(stream, "cwd=%s\n", cwd) < 0) {
        fclose(stream);
        return 11;
    }
    for (index = 0; index < argc; index++) {
        if (fprintf(
                stream,
                "argv[%d]=%zu:%s\n",
                index,
                strlen(argv[index]),
                argv[index]
            ) < 0) {
            fclose(stream);
            return 12;
        }
    }
    frontend_model = getenv("RAPTOR_FRONTEND_MODEL");
    if (fprintf(
            stream,
            "env.RAPTOR_FRONTEND_MODEL=%s\n",
            frontend_model == NULL ? "<unset>" : frontend_model
        ) < 0
            || fclose(stream) != 0) {
        return 13;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *model;
    const char *rejected_model;
    int capture_rc;

    capture_rc = write_capture(argc, argv);
    if (capture_rc != 0) {
        return capture_rc;
    }

    model = selected_model(argc, argv);
    rejected_model = getenv("RAPTOR_TEST_FRONTEND_REJECT_MODEL");
    if (model != NULL
            && rejected_model != NULL
            && strcmp(model, rejected_model) == 0) {
        fprintf(
            stderr,
            "native frontend fixture rejected model upstream: %s\n",
            model
        );
        return 64;
    }
    return 0;
}
