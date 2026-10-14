#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef OWNED_IMAGE_ID
#error "OWNED_IMAGE_ID must be defined"
#endif

#define FD_CONTROL 3
#define FD_LIVENESS 4
#define FD_ACTIVATION_STATUS 5
#define FD_WITNESS 6
#define FD_DISTRIBUTION 7
#define FD_PRIMARY_EXECUTABLE 8
#define FD_ALTERNATE_EXECUTABLE 9

#define FRAME_MAGIC UINT32_C(0x52525054)
#define FRAME_VERSION UINT16_C(1)
#define FRAME_PAYLOAD_BYTES UINT32_C(24)

#define EVENT_BOOTSTRAP_READY UINT16_C(1)
#define EVENT_ACTIVE_WAITING_READY UINT16_C(2)
#define EVENT_READY UINT16_C(3)
#define EVENT_SHAPE UINT16_C(4)
#define EVENT_CONTROLLED_EXITING UINT16_C(5)
#define EVENT_PROTOCOL_ERROR UINT16_C(6)

#define COMMAND_ACTIVATE UINT16_C(101)
#define COMMAND_RELEASE_READY UINT16_C(102)
#define COMMAND_CONTROLLED_EXIT UINT16_C(103)
#define COMMAND_REEXEC_SAME UINT16_C(104)
#define COMMAND_REEXEC_DIFFERENT UINT16_C(105)

#define SCENARIO_READY UINT32_C(1)
#define SCENARIO_DELAYED_READY UINT32_C(2)
#define SCENARIO_EXIT_BEFORE_READY UINT32_C(3)
#define SCENARIO_EXIT_AFTER_READY UINT32_C(4)
#define SCENARIO_ACTIVATION_FAILURE UINT32_C(5)
#define SCENARIO_SKIP_RUNTIME_MODULE UINT32_C(6)
#define SCENARIO_EXTRA_DISTRIBUTION_MAPPING UINT32_C(7)
#define SCENARIO_WRONG_MODULE_ROLE UINT32_C(8)
#define SCENARIO_MALFORMED_READY UINT32_C(9)
#define SCENARIO_DUPLICATE_READY UINT32_C(10)
#define SCENARIO_CONTROL_EOF UINT32_C(11)

#define SHAPE_NONE UINT32_C(0)
#define SHAPE_ONE_CHILD UINT32_C(1)
#define SHAPE_CHILD_AND_GRANDCHILD UINT32_C(2)

#define EXEC_STATUS_MAGIC UINT32_C(0x52524558)

#if defined(__GNUC__) || defined(__clang__)
__attribute__((used))
#endif
static const unsigned char sea_loader_payload[] =
    "RAPTOR_OWNED_RUNTIME_FAKE_SEA_LOADER_V1";

#if defined(__GNUC__) || defined(__clang__)
__attribute__((used))
#endif
static const uint32_t owned_image_id = OWNED_IMAGE_ID;

struct __attribute__((packed)) protocol_frame {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint32_t payload_bytes;
    uint32_t pid;
    uint32_t parent_pid;
    uint32_t process_group;
    uint32_t argument0;
    uint32_t argument1;
    uint32_t argument2;
};

struct __attribute__((packed)) exec_status_frame {
    uint32_t magic;
    int32_t error_number;
};

_Static_assert(sizeof(struct protocol_frame) == 36, "protocol frame size");
_Static_assert(sizeof(struct exec_status_frame) == 8, "exec status frame size");

static volatile sig_atomic_t stop_requested = 0;

static void handle_stop(int signum)
{
    (void)signum;
    stop_requested = 1;
}

static int install_signal_handlers(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_stop;
    if (sigemptyset(&action.sa_mask) != 0) {
        return -1;
    }
    if (sigaction(SIGTERM, &action, NULL) != 0
            || sigaction(SIGINT, &action, NULL) != 0) {
        return -1;
    }
    return 0;
}

static int bind_parent_lifetime(void)
{
    pid_t parent = getppid();

    if (parent <= 1 || prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) {
        return -1;
    }
    if (getppid() != parent) {
        return -1;
    }
    return 0;
}

static int frame_identity_matches(const struct protocol_frame *frame)
{
    return frame->pid == (uint32_t)getpid()
        && frame->parent_pid == (uint32_t)getppid()
        && frame->process_group == (uint32_t)getpgrp();
}

static int frame_is_valid(
    const struct protocol_frame *frame,
    uint16_t expected_type
)
{
    return frame->magic == FRAME_MAGIC
        && frame->version == FRAME_VERSION
        && frame->type == expected_type
        && frame->payload_bytes == FRAME_PAYLOAD_BYTES
        && frame_identity_matches(frame);
}

static int send_frame(
    uint16_t type,
    uint32_t argument0,
    uint32_t argument1,
    uint32_t argument2
)
{
    struct protocol_frame frame;
    ssize_t written;

    memset(&frame, 0, sizeof(frame));
    frame.magic = FRAME_MAGIC;
    frame.version = FRAME_VERSION;
    frame.type = type;
    frame.payload_bytes = FRAME_PAYLOAD_BYTES;
    frame.pid = (uint32_t)getpid();
    frame.parent_pid = (uint32_t)getppid();
    frame.process_group = (uint32_t)getpgrp();
    frame.argument0 = argument0;
    frame.argument1 = argument1;
    frame.argument2 = argument2;
    written = send(FD_CONTROL, &frame, sizeof(frame), MSG_NOSIGNAL);
    return written == (ssize_t)sizeof(frame) ? 0 : -1;
}

static int receive_frame(
    struct protocol_frame *frame,
    uint16_t expected_type,
    int flags
)
{
    unsigned char raw[sizeof(*frame) + 1];
    ssize_t count;

    count = recv(FD_CONTROL, raw, sizeof(raw), flags);
    if (count != (ssize_t)sizeof(*frame)) {
        return -1;
    }
    memcpy(frame, raw, sizeof(*frame));
    return frame_is_valid(frame, expected_type) ? 0 : -1;
}

static int write_exec_failure(int error_number)
{
    struct exec_status_frame frame;
    ssize_t written;

    frame.magic = EXEC_STATUS_MAGIC;
    frame.error_number = error_number;
    written = write(FD_ACTIVATION_STATUS, &frame, sizeof(frame));
    return written == (ssize_t)sizeof(frame) ? 0 : -1;
}

static int liveness_gone(void)
{
    struct pollfd item;
    unsigned char byte;
    ssize_t count;
    int result;

    item.fd = FD_LIVENESS;
    item.events = POLLIN | POLLHUP | POLLERR;
    item.revents = 0;
    result = poll(&item, 1, 0);
    if (result < 0) {
        return errno == EINTR ? 0 : 1;
    }
    if (result == 0) {
        return 0;
    }
    if ((item.revents & (POLLHUP | POLLERR)) != 0) {
        return 1;
    }
    if ((item.revents & POLLIN) != 0) {
        count = read(FD_LIVENESS, &byte, sizeof(byte));
        return count == 0;
    }
    return 0;
}

static void close_descendant_fds(void)
{
    (void)close(FD_CONTROL);
    (void)close(FD_DISTRIBUTION);
    (void)close(FD_PRIMARY_EXECUTABLE);
    (void)close(FD_ALTERNATE_EXECUTABLE);
}

static void wait_for_liveness_or_signal(pid_t nested_child)
{
    struct pollfd item;

    item.fd = FD_LIVENESS;
    item.events = POLLIN | POLLHUP | POLLERR;
    item.revents = 0;
    while (!stop_requested) {
        int result = poll(&item, 1, -1);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if ((item.revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            break;
        }
    }
    if (nested_child > 0) {
        (void)kill(nested_child, SIGTERM);
        while (waitpid(nested_child, NULL, 0) < 0 && errno == EINTR) {
        }
    }
    (void)close(FD_LIVENESS);
    _exit(0);
}

static int wait_for_gate(int gate_fd)
{
    unsigned char byte;
    ssize_t count;

    do {
        count = read(gate_fd, &byte, sizeof(byte));
    } while (count < 0 && errno == EINTR);
    return count == 0 ? 0 : -1;
}

static void acknowledge_witness_close(int gate_fd, int ack_fd, unsigned char tag)
{
    if (wait_for_gate(gate_fd) != 0) {
        _exit(70);
    }
    (void)close(gate_fd);
    (void)close(FD_WITNESS);
    if (write(ack_fd, &tag, sizeof(tag)) != (ssize_t)sizeof(tag)) {
        _exit(71);
    }
    (void)close(ack_fd);
}

static pid_t spawn_descendants(
    uint32_t shape,
    int gate_read_fd,
    int gate_write_fd,
    int ack_read_fd,
    int ack_write_fd
)
{
    pid_t child;

    if (shape == SHAPE_NONE) {
        return 0;
    }
    child = fork();
    if (child < 0) {
        return -1;
    }
    if (child == 0) {
        pid_t grandchild = 0;

        close_descendant_fds();
        (void)close(gate_write_fd);
        (void)close(ack_read_fd);
        if (shape == SHAPE_CHILD_AND_GRANDCHILD) {
            grandchild = fork();
            if (grandchild < 0) {
                _exit(72);
            }
            if (grandchild == 0) {
                acknowledge_witness_close(
                    gate_read_fd,
                    ack_write_fd,
                    (unsigned char)'G'
                );
                wait_for_liveness_or_signal(0);
            }
        }
        acknowledge_witness_close(
            gate_read_fd,
            ack_write_fd,
            (unsigned char)'C'
        );
        wait_for_liveness_or_signal(grandchild);
    }
    return child;
}

static int read_close_acknowledgements(int fd, uint32_t shape)
{
    unsigned int expected = shape == SHAPE_CHILD_AND_GRANDCHILD ? 2U
        : shape == SHAPE_ONE_CHILD ? 1U : 0U;
    unsigned int seen = 0;

    while (seen < expected) {
        unsigned char byte;
        ssize_t count = read(fd, &byte, sizeof(byte));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count != (ssize_t)sizeof(byte)
                || (byte != (unsigned char)'C' && byte != (unsigned char)'G')) {
            return -1;
        }
        ++seen;
    }
    return 0;
}

static int load_owned_module(const char *relative, const char *expected_role)
{
    char path[256];
    void *handle;
    void *symbol;
    const char *(*role_function)(void);
    int count;

    count = snprintf(
        path,
        sizeof(path),
        "/proc/self/fd/%d/%s",
        FD_DISTRIBUTION,
        relative
    );
    if (count < 0 || (size_t)count >= sizeof(path)) {
        return -1;
    }
    handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        return -1;
    }
    symbol = dlsym(handle, "owned_module_role");
    if (symbol == NULL) {
        return -1;
    }
    memcpy(&role_function, &symbol, sizeof(role_function));
    if (role_function == NULL || strcmp(role_function(), expected_role) != 0) {
        return -1;
    }
    return 0;
}

static int wait_for_release(void)
{
    struct protocol_frame frame;

    while (!stop_requested) {
        struct pollfd items[2];
        int result;

        items[0].fd = FD_CONTROL;
        items[0].events = POLLIN | POLLHUP | POLLERR;
        items[0].revents = 0;
        items[1].fd = FD_LIVENESS;
        items[1].events = POLLIN | POLLHUP | POLLERR;
        items[1].revents = 0;
        result = poll(items, 2, -1);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if ((items[1].revents & (POLLIN | POLLHUP | POLLERR)) != 0
                && liveness_gone()) {
            return -1;
        }
        if ((items[0].revents & (POLLHUP | POLLERR)) != 0) {
            return -1;
        }
        if ((items[0].revents & POLLIN) != 0) {
            if (receive_frame(&frame, COMMAND_RELEASE_READY, 0) != 0) {
                return -1;
            }
            return 0;
        }
    }
    return -1;
}

static void stop_descendants(pid_t child)
{
    if (child <= 0) {
        return;
    }
    (void)kill(child, SIGTERM);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
    }
}

static int active_loop(pid_t descendant)
{
    while (!stop_requested) {
        struct pollfd items[2];
        struct protocol_frame frame;
        int result;

        items[0].fd = FD_CONTROL;
        items[0].events = POLLIN | POLLHUP | POLLERR;
        items[0].revents = 0;
        items[1].fd = FD_LIVENESS;
        items[1].events = POLLIN | POLLHUP | POLLERR;
        items[1].revents = 0;
        result = poll(items, 2, -1);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if ((items[1].revents & (POLLIN | POLLHUP | POLLERR)) != 0
                && liveness_gone()) {
            break;
        }
        if ((items[0].revents & (POLLHUP | POLLERR)) != 0) {
            break;
        }
        if ((items[0].revents & POLLIN) == 0) {
            continue;
        }
        if (receive_frame(&frame, COMMAND_CONTROLLED_EXIT, MSG_PEEK) == 0) {
            if (receive_frame(&frame, COMMAND_CONTROLLED_EXIT, 0) != 0) {
                break;
            }
            (void)send_frame(EVENT_CONTROLLED_EXITING, 0, 0, 0);
            stop_descendants(descendant);
            (void)close(FD_LIVENESS);
            return 0;
        }
        if (receive_frame(&frame, COMMAND_REEXEC_SAME, MSG_PEEK) == 0) {
            static char *const argv[] = {
                (char *)"owned-runtime-host",
                (char *)"--reexec-hold",
                NULL,
            };
            static char *const empty_environment[] = {NULL};

            if (receive_frame(&frame, COMMAND_REEXEC_SAME, 0) != 0) {
                break;
            }
            fexecve(FD_PRIMARY_EXECUTABLE, argv, empty_environment);
            (void)send_frame(EVENT_PROTOCOL_ERROR, (uint32_t)errno, 0, 0);
            break;
        }
        if (receive_frame(&frame, COMMAND_REEXEC_DIFFERENT, MSG_PEEK) == 0) {
            static char *const argv[] = {
                (char *)"owned-runtime-host",
                (char *)"--reexec-hold",
                NULL,
            };
            static char *const empty_environment[] = {NULL};

            if (receive_frame(&frame, COMMAND_REEXEC_DIFFERENT, 0) != 0) {
                break;
            }
            fexecve(FD_ALTERNATE_EXECUTABLE, argv, empty_environment);
            (void)send_frame(EVENT_PROTOCOL_ERROR, (uint32_t)errno, 0, 0);
            break;
        }
        (void)send_frame(EVENT_PROTOCOL_ERROR, UINT32_C(1), 0, 0);
        break;
    }
    stop_descendants(descendant);
    (void)close(FD_LIVENESS);
    return 1;
}

static int run_bootstrap(void)
{
    struct protocol_frame activation;
    static char *const active_argv[] = {
        (char *)"owned-runtime-host",
        (char *)"--active",
        NULL,
    };
    static char *const empty_environment[] = {NULL};

    if (send_frame(EVENT_BOOTSTRAP_READY, 0, 0, owned_image_id) != 0) {
        return 20;
    }
    for (;;) {
        struct pollfd items[2];
        int result;

        items[0].fd = FD_CONTROL;
        items[0].events = POLLIN | POLLHUP | POLLERR;
        items[0].revents = 0;
        items[1].fd = FD_LIVENESS;
        items[1].events = POLLIN | POLLHUP | POLLERR;
        items[1].revents = 0;
        result = poll(items, 2, -1);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return 21;
        }
        if ((items[1].revents & (POLLIN | POLLHUP | POLLERR)) != 0
                && liveness_gone()) {
            return 22;
        }
        if ((items[0].revents & (POLLHUP | POLLERR)) != 0) {
            return 23;
        }
        if ((items[0].revents & POLLIN) == 0) {
            continue;
        }
        if (receive_frame(&activation, COMMAND_ACTIVATE, MSG_PEEK) != 0) {
            (void)send_frame(EVENT_PROTOCOL_ERROR, UINT32_C(2), 0, 0);
            return 24;
        }
        break;
    }
    if (activation.argument0 == SCENARIO_ACTIVATION_FAILURE) {
        (void)write_exec_failure(ENOEXEC);
        return 25;
    }
    if (fcntl(FD_ACTIVATION_STATUS, F_SETFD, FD_CLOEXEC) != 0) {
        (void)write_exec_failure(errno);
        return 26;
    }
    fexecve(FD_PRIMARY_EXECUTABLE, active_argv, empty_environment);
    (void)write_exec_failure(errno);
    return 27;
}

static int run_active(void)
{
    struct protocol_frame activation;
    int gate[2] = {-1, -1};
    int acknowledgement[2] = {-1, -1};
    pid_t descendant = 0;
    uint32_t scenario;
    uint32_t shape;
    uint32_t module_count = 0;

    if (prctl(PR_SET_NAME, "MainThread", 0, 0, 0) != 0) {
        return 30;
    }
    if (send_frame(EVENT_ACTIVE_WAITING_READY, 0, 0, owned_image_id) != 0) {
        return 31;
    }
    if (receive_frame(&activation, COMMAND_ACTIVATE, 0) != 0) {
        return 32;
    }
    scenario = activation.argument0;
    shape = activation.argument1;
    if (shape > SHAPE_CHILD_AND_GRANDCHILD) {
        return 33;
    }

    if (scenario != SCENARIO_SKIP_RUNTIME_MODULE) {
        if (load_owned_module(
                "prebuilds/linux-x64/runtime.node",
                scenario == SCENARIO_WRONG_MODULE_ROLE
                    ? "cli-native.node" : "runtime.node") != 0) {
            (void)send_frame(EVENT_PROTOCOL_ERROR, UINT32_C(3), 0, 0);
            return active_loop(0);
        }
        ++module_count;
    }
    if (load_owned_module(
            "prebuilds/linux-x64/cli-native.node",
            "cli-native.node") != 0) {
        (void)send_frame(EVENT_PROTOCOL_ERROR, UINT32_C(4), 0, 0);
    return active_loop(0);
    }
    ++module_count;
    if (scenario == SCENARIO_EXTRA_DISTRIBUTION_MAPPING) {
        if (load_owned_module(
                "prebuilds/linux-x64/extra-owned.node",
                "extra-owned.node") != 0) {
            (void)send_frame(EVENT_PROTOCOL_ERROR, UINT32_C(5), 0, 0);
            return active_loop(0);
        }
        ++module_count;
    }

    if (pipe2(gate, O_CLOEXEC) != 0 || pipe2(acknowledgement, O_CLOEXEC) != 0) {
        (void)send_frame(EVENT_PROTOCOL_ERROR, UINT32_C(6), 0, 0);
        return 37;
    }
    descendant = spawn_descendants(
        shape,
        gate[0],
        gate[1],
        acknowledgement[0],
        acknowledgement[1]
    );
    if (descendant < 0) {
        (void)send_frame(EVENT_PROTOCOL_ERROR, UINT32_C(7), 0, 0);
        return 38;
    }
    (void)close(gate[0]);
    (void)close(acknowledgement[1]);

    if (scenario == SCENARIO_CONTROL_EOF) {
        (void)close(FD_CONTROL);
        stop_descendants(descendant);
        return 39;
    }
    if (wait_for_release() != 0) {
        stop_descendants(descendant);
        return 40;
    }
    (void)close(gate[1]);
    gate[1] = -1;
    if (read_close_acknowledgements(acknowledgement[0], shape) != 0) {
        stop_descendants(descendant);
        return 41;
    }
    (void)close(acknowledgement[0]);
    acknowledgement[0] = -1;
    if (fcntl(FD_WITNESS, F_SETFD, FD_CLOEXEC) != 0) {
        stop_descendants(descendant);
        return 42;
    }
    if (scenario == SCENARIO_EXIT_BEFORE_READY) {
        stop_descendants(descendant);
        (void)close(FD_LIVENESS);
        return 43;
    }
    if (send_frame(EVENT_SHAPE, shape, module_count, owned_image_id) != 0) {
        stop_descendants(descendant);
        return 44;
    }
    if (scenario == SCENARIO_MALFORMED_READY) {
        struct protocol_frame malformed;

        memset(&malformed, 0, sizeof(malformed));
        malformed.magic = FRAME_MAGIC;
        malformed.version = FRAME_VERSION;
        malformed.type = EVENT_READY;
        malformed.payload_bytes = FRAME_PAYLOAD_BYTES;
        malformed.pid = (uint32_t)getpid();
        malformed.parent_pid = (uint32_t)getppid();
        malformed.process_group = (uint32_t)getpgrp();
        (void)send(
            FD_CONTROL,
            &malformed,
            sizeof(malformed) - 1,
            MSG_NOSIGNAL
        );
        return active_loop(descendant);
    }
    if (send_frame(EVENT_READY, shape, module_count, owned_image_id) != 0) {
        stop_descendants(descendant);
        return 46;
    }
    if (scenario == SCENARIO_DUPLICATE_READY) {
        if (send_frame(EVENT_READY, shape, module_count, owned_image_id) != 0) {
            stop_descendants(descendant);
            return 47;
        }
    }
    if (scenario == SCENARIO_EXIT_AFTER_READY) {
        stop_descendants(descendant);
        (void)close(FD_LIVENESS);
        return 48;
    }
    return active_loop(descendant);
}

static int run_reexec_hold(void)
{
    if (prctl(PR_SET_NAME, "MainThread", 0, 0, 0) != 0) {
        return 50;
    }
    return active_loop(0);
}

int main(int argc, char **argv)
{
    if (argc != 2 || strcmp(argv[0], "owned-runtime-host") != 0) {
        return 2;
    }
    if (sea_loader_payload[0] != (unsigned char)'R') {
        return 3;
    }
    if (bind_parent_lifetime() != 0 || install_signal_handlers() != 0) {
        return 4;
    }
    if (strcmp(argv[1], "--bootstrap") == 0) {
        return run_bootstrap();
    }
    if (strcmp(argv[1], "--active") == 0) {
        return run_active();
    }
    if (strcmp(argv[1], "--reexec-hold") == 0) {
        return run_reexec_hold();
    }
    return 5;
}
