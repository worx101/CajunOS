#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/utsname.h>
#include <unistd.h>

#define FIRST_BOOT_ARGUMENT "cajunos.first_boot=1"
#define FIRST_BOOT_KEY "cajunos.first_boot="
#define CMDLINE_CAPACITY 4096U

enum cmdline_result {
    CMDLINE_VALID = 0,
    CMDLINE_MISSING_OR_INVALID = 1,
    CMDLINE_DUPLICATE = 2,
};

static int is_cmdline_space(char value)
{
    return value == ' ' || value == '\t' || value == '\n' ||
           value == '\r' || value == '\v' || value == '\f';
}

static enum cmdline_result validate_cmdline(const char *cmdline)
{
    const size_t key_length = sizeof(FIRST_BOOT_KEY) - 1U;
    const size_t expected_length = sizeof(FIRST_BOOT_ARGUMENT) - 1U;
    unsigned int matches = 0U;
    const char *cursor = cmdline;

    while (*cursor != '\0') {
        const char *begin;
        size_t length;

        while (is_cmdline_space(*cursor))
            ++cursor;
        if (*cursor == '\0')
            break;

        begin = cursor;
        while (*cursor != '\0' && !is_cmdline_space(*cursor))
            ++cursor;
        length = (size_t)(cursor - begin);

        if (length >= key_length &&
            memcmp(begin, FIRST_BOOT_KEY, key_length) == 0) {
            if (length != expected_length ||
                memcmp(begin, FIRST_BOOT_ARGUMENT, expected_length) != 0)
                return CMDLINE_MISSING_OR_INVALID;
            ++matches;
            if (matches > 1U)
                return CMDLINE_DUPLICATE;
        }
    }

    return matches == 1U ? CMDLINE_VALID : CMDLINE_MISSING_OR_INVALID;
}

static int is_safe_evidence_value(const char *value)
{
    const unsigned char *cursor = (const unsigned char *)value;
    size_t length = 0U;

    if (*cursor == '\0')
        return 0;
    for (; *cursor != '\0'; ++cursor) {
        ++length;
        if (length > 128U)
            return 0;
        if ((*cursor >= 'a' && *cursor <= 'z') ||
            (*cursor >= 'A' && *cursor <= 'Z') ||
            (*cursor >= '0' && *cursor <= '9') ||
            *cursor == '.' || *cursor == '_' || *cursor == '-' ||
            *cursor == '+')
            continue;
        return 0;
    }
    return 1;
}

#ifdef CAJUNOS_FIRST_BOOT_UNIT_TEST

int main(int argc, char **argv)
{
    if (argc != 3)
        return 64;
    if (strcmp(argv[1], "cmdline") == 0)
        return (int)validate_cmdline(argv[2]);
    if (strcmp(argv[1], "evidence-value") == 0)
        return is_safe_evidence_value(argv[2]) ? 0 : 1;
    return 64;
}

#else

#ifndef CAJUNOS_EXPECTED_RELEASE
#error "CAJUNOS_EXPECTED_RELEASE must name the built kernel release"
#endif

#ifndef CAJUNOS_BUILD_ID
#error "CAJUNOS_BUILD_ID must name the immutable first-boot build"
#endif

static int console_fd = STDERR_FILENO;

static void write_all(const char *message, size_t length)
{
    while (length > 0U) {
        ssize_t written = write(console_fd, message, length);

        if (written > 0) {
            message += written;
            length -= (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        break;
    }
}

static void emit_line(const char *message)
{
    write_all(message, strlen(message));
    write_all("\n", 1U);
}

static void emit_evidence(const char *marker, const char *value)
{
    char line[512];
    int length = snprintf(line, sizeof(line), "%s %s", marker, value);

    if (length <= 0 || (size_t)length >= sizeof(line)) {
        emit_line("CAJUNOS_KERNEL_FIRST_BOOT_FAIL evidence-overflow");
        return;
    }
    emit_line(line);
}

__attribute__((noreturn)) static void finish_reboot(const char *failure)
{
    if (failure != NULL) {
        char line[256];
        int length = snprintf(line, sizeof(line),
                              "CAJUNOS_KERNEL_FIRST_BOOT_FAIL %s", failure);

        if (length > 0 && (size_t)length < sizeof(line))
            emit_line(line);
        else
            emit_line("CAJUNOS_KERNEL_FIRST_BOOT_FAIL invalid-reason");
    }

    sync();
    if (reboot(RB_AUTOBOOT) < 0)
        emit_line("CAJUNOS_KERNEL_FIRST_BOOT_FAIL reboot-returned");
    _exit(111);
}

static void establish_console(void)
{
    int fd = open("/dev/console", O_RDWR | O_NOCTTY | O_CLOEXEC);

    if (fd < 0) {
        emit_line("CAJUNOS_KERNEL_FIRST_BOOT_FAIL console-open");
        _exit(111);
    }
    if (dup2(fd, STDIN_FILENO) < 0 ||
        dup2(fd, STDOUT_FILENO) < 0 ||
        dup2(fd, STDERR_FILENO) < 0) {
        console_fd = fd;
        finish_reboot("console-dup");
    }
    if (fd > STDERR_FILENO)
        close(fd);
    console_fd = STDOUT_FILENO;
}

static int read_cmdline(char *buffer, size_t capacity)
{
    size_t used = 0U;
    int fd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

    if (fd < 0)
        return -1;
    while (used + 1U < capacity) {
        ssize_t count = read(fd, buffer + used, capacity - used - 1U);

        if (count > 0) {
            used += (size_t)count;
            continue;
        }
        if (count == 0)
            break;
        if (errno == EINTR)
            continue;
        close(fd);
        return -2;
    }
    if (used + 1U == capacity) {
        char extra;
        ssize_t count;

        do {
            count = read(fd, &extra, 1U);
        } while (count < 0 && errno == EINTR);
        if (count != 0) {
            close(fd);
            return -3;
        }
    }
    close(fd);
    buffer[used] = '\0';
    return 0;
}

int main(void)
{
    struct utsname identity;
    char cmdline[CMDLINE_CAPACITY];
    enum cmdline_result cmdline_status;

    establish_console();
    emit_line("CAJUNOS_KERNEL_FIRST_BOOT_BEGIN");

    if (getpid() != 1)
        finish_reboot("not-pid1");
    emit_line("CAJUNOS_KERNEL_FIRST_BOOT_PID1_OK");

    if (!is_safe_evidence_value(CAJUNOS_EXPECTED_RELEASE) ||
        !is_safe_evidence_value(CAJUNOS_BUILD_ID))
        finish_reboot("invalid-build-metadata");
    if (uname(&identity) < 0)
        finish_reboot("uname");
    if (strcmp(identity.machine, "x86_64") != 0)
        finish_reboot("wrong-machine");
    if (strcmp(identity.release, CAJUNOS_EXPECTED_RELEASE) != 0)
        finish_reboot("wrong-release");
    emit_evidence("CAJUNOS_KERNEL_FIRST_BOOT_UNAME", identity.release);
    emit_evidence("CAJUNOS_KERNEL_FIRST_BOOT_BUILD_ID", CAJUNOS_BUILD_ID);

    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC,
              NULL) < 0)
        finish_reboot("proc-mount");
    emit_line("CAJUNOS_KERNEL_FIRST_BOOT_PROC_OK");

    switch (read_cmdline(cmdline, sizeof(cmdline))) {
    case -1:
        finish_reboot("cmdline-open");
    case -2:
        finish_reboot("cmdline-read");
    case -3:
        finish_reboot("cmdline-too-long");
    default:
        break;
    }
    cmdline_status = validate_cmdline(cmdline);
    if (cmdline_status == CMDLINE_DUPLICATE)
        finish_reboot("cmdline-duplicate");
    if (cmdline_status != CMDLINE_VALID)
        finish_reboot("cmdline-token");
    emit_line("CAJUNOS_KERNEL_FIRST_BOOT_CMDLINE_OK");

    emit_line("CAJUNOS_KERNEL_FIRST_BOOT_OK");
    finish_reboot(NULL);
}

#endif
