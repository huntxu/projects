#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "drcom.h"

#define LOCKFILE "/var/run/drcom.pid"
#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

extern pcap_t *handle;
extern enum STATE state;
extern int exit_flag;

static int lockfile;

static void flock_reg()
{
    u_char buf[16];
    struct flock fl;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    fl.l_type = F_WRLCK;
    fl.l_pid = getpid();

    if ( fcntl(lockfile, F_SETLKW, &fl) < 0 ) {
        perror("fcntl_reg");
        exit(EXIT_FAILURE);
    }

    if ( ftruncate(lockfile, 0) ) {
        perror("ftruncate");
        exit(EXIT_FAILURE);
    }
    sprintf(buf, "%ld", (long)fl.l_pid);
    if ( write(lockfile, buf, strlen(buf)+1) == -1 ) {
        perror("writing pid to lockfile failed");
        exit(EXIT_FAILURE);
    }
    return;
}

static int is_running()
{
    struct flock fl;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    fl.l_type = F_WRLCK;

    if ( fcntl(lockfile, F_GETLK, &fl) < 0 ) {
        perror("fcntl_get");
        exit(EXIT_FAILURE);
    }

    if (exit_flag) {
        if (fl.l_type != F_UNLCK) {
            if ( kill(fl.l_pid, SIGINT) == -1 ) {
                perror("kill");
            }
            fprintf(stdout, "kill signal sent to daemon pid %d\n",fl.l_pid);
            exit(EXIT_SUCCESS);
        }
        else {
            fprintf(stderr, "no any drcom daemon is running\n"); 
            exit(EXIT_FAILURE);
        }
    }
    if (fl.l_type == F_UNLCK) {
        flock_reg();
        return 0;
    }
    return fl.l_pid;
}

void init_daemon()
{
    pid_t pid = fork();
    int fd0;

    if ( pid < 0 ) {
        perror("fork");
        error_handle(-2);
    }
    else if ( pid != 0 ) {
        fprintf(stdout, "drcom forked background with pid [%d]\n", pid);
        exit(EXIT_SUCCESS);
    }

    setsid();
    if ( chdir("/tmp") ) {
        perror("chdir");
        error_handle(-2);
    }
    umask(0);
    flock_reg();

    fd0 = open("/dev/null", O_RDWR);
    dup2(fd0, STDIN_FILENO);
    dup2(fd0, STDOUT_FILENO);
    dup2(fd0, STDERR_FILENO);
    close(fd0);
    return;
}

int main(int argc, char **argv)
{
    init_arguments(&argc, &argv);

    if (getuid()) {
        printf("drcom4GDUFS: You must be root to do that!\n");
        exit(EXIT_FAILURE);
    }

    //open the lockfile
    lockfile = open (LOCKFILE, O_RDWR | O_CREAT , LOCKMODE);
    if (lockfile < 0){
        perror ("lockfile");
        exit(EXIT_FAILURE);
    }

    //is_running
    int ins_pid = is_running();
    if (ins_pid) {
        fprintf(stderr,"another drcom is running: pid %d\n", ins_pid);
        exit(EXIT_FAILURE);
    }

    signal (SIGINT, error_handle);
    signal (SIGTERM, error_handle);    

    init_info();
    init_device();

    //TODO: what if I cannot get a packet after the eapol_logoff packet
    //      sent, here should be a alarm to resend this packet or even 
    //      the eapol_start packet, and the alarm shoule be cancelled when
    //      eap_request_identity received, and here should init the state.
    send_eap_packet(EAPOL_LOGOFF);
    //first packet send
    fprintf(stdout, "start packet sent\n");

    //进入回呼循环。以后的动作由回呼函数get_packet驱动，
    //直到pcap_break_loop执行，退出程序。
    state = STARTED;
    pcap_loop (handle, -2, get_packet, NULL);   /* main loop */
    pcap_close (handle);
    return 0;
}
