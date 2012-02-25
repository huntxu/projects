#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <getopt.h>

#include <linux/joystick.h>
#include <linux/input.h>

int running;

void generate_key_event(int fd, uint32_t button_number, int32_t value)
{
    uint16_t button[10] = {KEY_ESC,
                           KEY_LEFTSHIFT,
                           0,
                           KEY_ENTER,
                           KEY_LEFTCTRL,
                           KEY_LEFTALT,
                           0, 0, 0, 0};

    struct input_event input_e;
    if (button[button_number] == 0) {
        return;
    }

    input_e.type = EV_MSC;
    input_e.code = MSC_SCAN;
    input_e.value = (int32_t)button[button_number];
    gettimeofday(&input_e.time, 0);
    if (write(fd, &input_e, sizeof(struct input_event))
        != sizeof(struct input_event)) {
        perror("Generating key scan event failed");
        exit(EXIT_FAILURE);
    }

    input_e.type = EV_KEY;
    input_e.code = button[button_number];
    input_e.value = value;
    gettimeofday(&input_e.time, 0);
    if (write(fd, &input_e, sizeof(struct input_event))
        != sizeof(struct input_event)) {
        perror("Generating key event failed");
        exit(EXIT_FAILURE);
    }

    input_e.type = 0;
    input_e.code = 0;
    input_e.value = 0;
    gettimeofday(&input_e.time, 0);
    if (write(fd, &input_e, sizeof(struct input_event))
        != sizeof(struct input_event)) {
        perror("Simulating key failed");
        exit(EXIT_FAILURE);
    }

    return;
}

void exit_daemon(int sig)
{
    if (remove("/var/run/fiki.pid") != 0) {
        perror("Removing pid file failed");
    }
    running = 0;
    return;
}

void flock_reg(int lockfile, pid_t pid)
{
    uint8_t buf[16];
    struct flock fl;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    fl.l_type = F_WRLCK;
    fl.l_pid = getpid();

    if (fcntl(lockfile, F_SETLKW, &fl) < 0) {
        perror("Locking pid file failed");
        exit(EXIT_FAILURE);
    }

    if (ftruncate(lockfile, 0)) {
        perror("Truncating pid file failed");
    }

    sprintf(buf, "%ld", (long)fl.l_pid);
    if (write(lockfile, buf, strlen(buf)+1) == -1) {
        perror("Writing pid to pid file failed");
        exit(EXIT_FAILURE);
    }

    return;
}

pid_t running_check(int lockfile, int killflag)
{
    struct flock fl;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    fl.l_type = F_WRLCK;

    if (fcntl(lockfile, F_GETLK, &fl) < 0) {
        perror("Getting pid file lock state failed");
        exit(EXIT_FAILURE);
    }

    if (killflag) {
        if (fl.l_type == F_UNLCK) {
            fprintf(stderr, "Error: no any fiki daemon is runing\n");
            exit(EXIT_FAILURE);
        }
        else {
            if (kill(fl.l_pid, SIGTERM) == -1) {
                perror("Kill fiki daemon failed");
                exit(EXIT_FAILURE);
            }
            fprintf(stdout, "Killing fiki daemon, pid: %d\n", fl.l_pid);
            exit(EXIT_SUCCESS);
        }
    }

    if (fl.l_type == F_UNLCK) {
        flock_reg(lockfile, fl.l_pid);
        return 0;
    }
    
    return fl.l_pid;
}

void init_daemon(int lockfile)
{
    pid_t pid = fork();
    int fd0;

    if (pid < 0) {
        perror("Forking process to background failed");
        exit(EXIT_FAILURE);
    }
    else if (pid != 0) {
        fprintf(stdout, "fiki forked to backgroud with pid %d\n", pid);
        exit(EXIT_SUCCESS);
    }

    setsid();
    if (chdir("/tmp")) {
        perror("Changing working directory failed");
        exit(EXIT_FAILURE);
    }
    umask(0);
    flock_reg(lockfile, pid);

    fd0 = open("/dev/null", O_RDWR);
    dup2(fd0, STDIN_FILENO);
    dup2(fd0, STDOUT_FILENO);
    dup2(fd0, STDERR_FILENO);
    close(fd0);

    return;
}

void init_arguments(int *argc,
                    char ***argv,
                    char *keyboard,
                    char *joystick,
                    int *killflag)
{
    int c;
    int keyboard_notprovided = 1;
    int joystick_notprovided = 1;
    struct option long_options[] =
    {
        {"kill",        no_argument,        0,  'K'},
        {"keyboard",    required_argument,  0,  'k'},
        {"joystick",    required_argument,  0,  'j'},
        {0, 0, 0, 0}
    };

    while (1) {
        int option_index = 0;
        c = getopt_long((*argc), (*argv), "k:j:K",
                        long_options, &option_index);

        if (c == -1) break;

        switch (c) {
            case 0:
                break;
            case 'K':
                *killflag = 1;
                break;
            case 'k':
                strncpy(keyboard, optarg, 20);
                keyboard_notprovided = 0;
                break;
            case 'j':
                strncpy(joystick, optarg, 20);
                joystick_notprovided = 0;
                break;
            case '?':
                if (optopt == 'k' || optopt == 'j') {
                    fprintf(stderr,
                            "Option -%c requires an argument.\n",
                            optopt);
                }
                exit(EXIT_FAILURE);
            default:
                fprintf(stderr, "Unknown option `\\x%x'.\n", c);
                exit(EXIT_FAILURE);
        }
    }

    if (*killflag == 0) {
        if (keyboard_notprovided) {
            fprintf(stderr, "You must specify a keyboard device.\n");
            exit(EXIT_FAILURE);
        }
        if (joystick_notprovided) {
            fprintf(stderr, "You must specify a joystick device.\n");
            exit(EXIT_FAILURE);
        }
    }

    return;
}

int main(int argc, char **argv)
{
    char keyboard_dev[20];
    char joystick_dev[20];
    int killflag = 0;
    bzero(keyboard_dev, 20);
    bzero(joystick_dev, 20);

    init_arguments(&argc, &argv, keyboard_dev, joystick_dev, &killflag);

    if (setuid(0) != 0) {
        perror("Setting uid to 0 failed");
        exit(EXIT_FAILURE);
    }
    if (getuid()) {
        fprintf(stderr, "Unknown error\n");
        exit(EXIT_FAILURE);
    }

    int lockfile = open("/var/run/fiki.pid",
                        O_RDWR | O_CREAT,
                        S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (lockfile < 0) {
        perror("Opening lockfile failed");
        exit(EXIT_FAILURE);
    }

    pid_t pid = running_check(lockfile, killflag);
    if (pid) {
        fprintf(stderr, "A fiki daemon is already running, pid %d\n", pid);
        exit(EXIT_FAILURE);
    }

    int joystick_fd = open(joystick_dev, O_RDONLY);
    int keyboard_fd = open(keyboard_dev, O_WRONLY);
    fcntl(joystick_fd, F_SETFL, O_NONBLOCK);
    fcntl(keyboard_fd, F_SETFL, O_NONBLOCK);

    signal(SIGTERM, exit_daemon);
    init_daemon(lockfile);

    struct js_event js_e;
    running = 1;

    while (running) {
        while (read(joystick_fd, &js_e, sizeof(struct js_event)) == sizeof(struct js_event)) {
            if (!((js_e.type & JS_EVENT_INIT) || (js_e.type & JS_EVENT_AXIS))) {
                /* we only focus on JS_EVENT_BUTTON */
                generate_key_event(keyboard_fd, (uint32_t)js_e.number, (int32_t)js_e.value);
            }
        }
        if (errno != EAGAIN) {
            perror("error reading joystick");
        }
        usleep(120000);
    }

    if (js_e.value == 1)
    {
        /* release the last pressed key */
        generate_key_event(keyboard_fd, (uint32_t)js_e.number, 0);
    }

    close(keyboard_fd);
    close(joystick_fd);
    exit(EXIT_SUCCESS);
}
