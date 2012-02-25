#include <getopt.h>
#include <termios.h>
#include "drcom.h"

/* global variables */
u_char errbuf[PCAP_ERRBUF_SIZE]; //error buffer
enum STATE state; //program state
pcap_t *handle;
int exit_flag;

/* network information */
static u_char multicast_mac[ETH_ALEN]={0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};
u_char local_mac[ETH_ALEN];
static u_char interface[16];
static u_char dhclientcmd[20];
static u_char dhclientreleasecmd[20];
u_char local_ip[4];
u_char server_ip[4];

static u_int dhcp=0;

/* user information */
#define USERNAME_LEN 20
u_char username[20];
u_char password[20];
int username_length;
int password_length;

/* md5 challenge */
u_char md5_challenge[16];
u_char md5_digest[16];
static u_char ehid;
static u_char md5_send_times = 0x00;

/* trailers */
#define TRAILER1_LEN 0x6e
#define TRAILER2_LEN 0x28
static u_char trailer1[TRAILER1_LEN]={0xff, 0xff, 0x37, 0x77, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf5, 0x71, 0x00, 0x00, 0x13, 0x11, 0x38, 0x30, 0x32, 0x31, 0x78, 0x2e, 0x65, 0x78, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x11, 0x00, 0x28, 0x1a, 0x28, 0x00, 0x00, 0x13, 0x11, 0x17, 0x22, 0x92, 0x68, 0x64, 0x66, 0x92, 0x94, 0x62, 0x66, 0x91, 0x93, 0x95, 0x62, 0x93, 0x93, 0x91, 0x94, 0x64, 0x61, 0x64, 0x64, 0x65, 0x66, 0x68, 0x94, 0x98, 0xa7, 0x61, 0x67, 0x65, 0x67, 0x9c, 0x6b};
static u_char trailer2[TRAILER2_LEN]={0x00, 0x00, 0x13, 0x11, 0x18, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* data buffer */
static u_char data_buffer[0xff];

void error_handle(int sig)
{
    if ( sig == -2 ) {
        fprintf(stderr, "an error occured, exiting\n");
    }
    else {
        fprintf(stdout, "user interrupted\n");
    }

    if (dhcp == 1) {
        if ( system(dhclientreleasecmd) == -1 ) {
            fprintf(stderr, "error while releasing dhcp\n");
        }
    }
    if (state == ONLINE) {
        send_eap_packet(EAPOL_LOGOFF);
    }
    pcap_breakloop(handle);
    return;
}

void send_eap_packet(enum EAPSendType send_type)
{
    int data_length = 0;
   
    struct ether_header *ethh
        = (struct ether_header *) (&data_buffer[data_length]);
    memcpy(ethh->ether_dhost, multicast_mac, 6);
    memcpy(ethh->ether_shost, local_mac, 6);
    ethh->ether_type = htons(0x888e);
    data_length += ETH_HLEN;

    struct auth_header *authh
        = (struct auth_header *) (&data_buffer[data_length]);
    authh -> eapol_version = 0x01;
    authh -> eapol_type= 0x02;
    authh -> eapol_length = htons(0x0000);
    data_length += AUTH_HLEN;
    struct eap_header *eaph
        = (struct eap_header *) (&data_buffer[data_length]);

    if ( send_type & NEED_EAP_HEADER ) {
        authh -> eapol_type = 0x00;
        authh -> eapol_length = htons(0x0019);
        eaph -> eap_code = 0x02;
        eaph -> eap_id = ehid;
        eaph -> eap_length = htons(0x0019);
        eaph -> eap_type = 0x01;

        username[username_length+1] = 0x44;
        username[username_length+2] = 0x61;
        username[username_length+3] = 0x00;

        data_length += EAP_HLEN;
    }

    if ( send_type & NEED_MD5 ) {
        authh -> eapol_length = htons(0x002a);
        eaph -> eap_length = htons(0x002a);
        eaph -> eap_type = 0x04;

        username[username_length+3] = 0x02;
        username[username_length+4] = md5_send_times++;
        
        data_buffer[data_length] = 0x10;
        data_length += 1;
        memcpy(&data_buffer[data_length], md5_digest, 0x10);
        data_length += 0x10;
    }

    if ( send_type & NEED_USERNAME ) {
        memcpy(&data_buffer[data_length], username, USERNAME_LEN);
        data_length += USERNAME_LEN;
    }

    if ( send_type & NEED_TRAILER1 ) {
        memcpy(&data_buffer[data_length], trailer1, TRAILER1_LEN);
        data_length += TRAILER1_LEN;
    }

    if ( send_type & NEED_TRAILER2 ) {
        memcpy(&data_buffer[data_length], trailer2, TRAILER2_LEN);
        data_length += TRAILER2_LEN;
    }

    if ( pcap_sendpacket(handle, data_buffer, data_length) ) {
        fprintf(stderr, "!!FATAL: Error Sending packet: %s\n", pcap_geterr(handle));
        error_handle(-2);
    }
    return;
}

void get_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct eap_header *eap_header
        = (struct eap_header *) (&packet[ETH_HLEN+AUTH_HLEN]);

    ehid = eap_header->eap_id;
    switch (eap_header->eap_code) {
        case EAP_CODE_REQUEST:
            switch (eap_header->eap_type) {
                case EAP_REQUEST_IDENTITY:
                    if (state == STARTED) {
                        fprintf(stdout, "Identification Received\n");
                        state = IDENTIFIED;
                        send_eap_packet(EAP_RESPONSE_IDENTITY);
                    }
                    else {
                        fprintf(stdout, "Warning: we haven't started\n");
                    }
                    return;
                case EAP_REQUEST_NOTIFICATION:
                /* got this packet if authentication failed or in use*/
                    fprintf(stdout, "Server Notification: %s\n",
                            packet+ETH_HLEN+AUTH_HLEN+EAP_HLEN);
                    send_eap_packet(EAP_RESPONSE_MD5_CHALLENGE);
                    return;
                case EAP_REQUEST_MD5_CHALLENGE:
                    state = AUTHED;
                    fprintf(stdout, "MD5 Challenge Received\n");

                    memcpy(md5_challenge,
                           packet+ETH_HLEN+AUTH_HLEN+EAP_HLEN+0x01,
                           0x10);
                    md5digest();

                    send_eap_packet(EAP_RESPONSE_MD5_CHALLENGE);
                    return;
            }
        case EAP_CODE_SUCCESS:
            state = ONLINE;
            fprintf(stdout, "Login Successfully\n");
            if ( system(dhclientcmd) == -1 ) {
                fprintf(stderr, "Error while executing dhclient\n");
                error_handle(-2);
            }
            dhcp = 1;
            get_ip();
            if ( init_udp() == -1) {
                error_handle(-2);
            }
            init_daemon();
            alarm(31);
            return;
        case EAP_CODE_FAILURE:
            if ( state == ONLINE || state == AUTHED) {
                fprintf(stdout, "Logout\n");
                pcap_breakloop(handle);
            }
            return;
    }
    fprintf(stderr, "FATAL: Unknown packet[eap_code(%02x), eap_id(%02x), eap_type(%02x)]\n", eap_header->eap_code, eap_header->eap_id, eap_header->eap_type);
    fprintf(stderr, "Waring: I won't respond to this unknown packet\n");
    return;
}

void init_device()
{
    struct bpf_program fp;
    struct ifreq ifr;
    char filter_exp[51];

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("error creating socket to get local mac");
        exit(EXIT_FAILURE);
    }

    strcpy(ifr.ifr_name, interface);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("error getting local mac");
        exit(EXIT_FAILURE);
    }

    memcpy(local_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

    handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", interface);
        exit(EXIT_FAILURE);
    }

    //TODO: well, don't use hard code, I tell you again.
    sprintf(filter_exp, "ether dst 01:80:c2:00:00:03 and ether proto 0x888e");
    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    pcap_freecode(&fp);
    return;
}

void init_info()
{
    struct termios term;
    if (tcgetattr(STDIN_FILENO, &term) == -1) {
        perror("tcgetattr");
        exit(EXIT_FAILURE);
    }
    term.c_lflag &= ~ECHO;

    bzero(username, 20);
    bzero(password, 20);
    
    fprintf(stdout, "enter your username: ");
    if (fgets(username, 20, stdin) == NULL) {
        perror("fgets");
        exit(EXIT_FAILURE);
    }
    /* a newline will be read and stored into the buffer by fgets, *
     * just strip it.                                              */
    username_length = strlen(username) - 1;
    username[username_length] = 0;
    username_length = strlen(username);
    if (username_length == 0) {
        fprintf(stderr, "you must enter your username!\n");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "enter your password: ");
    /* don't echo the password */
    if (tcsetattr(STDIN_FILENO, TCSANOW, &term) == -1) {
        perror("tcsetattr");
        exit(EXIT_FAILURE);
    }
    if (fgets(password, 20, stdin) == NULL) {
        perror("fgets");
        exit(EXIT_FAILURE);
    }
    /* restore */
    term.c_lflag |= ECHO;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &term) == -1) {
        perror("tcsetattr");
        exit(EXIT_FAILURE);
    }

    password_length = strlen(password) - 1;
    password[password_length] = 0;
    password_length = strlen(password);
    fprintf(stdout, "\n");
    if (password_length == 0) {
        fprintf(stderr, "you must enter your password!\n");
        exit(EXIT_FAILURE);
    }

    if (interface[0] == '\0') {
        strncpy(interface, "eth0", 4);
    }

    if (dhclientcmd[0] == '\0') {
        strncpy(dhclientcmd, "dhclient", 8);
    }

    if (dhclientreleasecmd[0] == '\0') {
        strncpy(dhclientreleasecmd, "dhclient -r", 11);
    }

    dhclientcmd[strlen(dhclientcmd)] = ' ';
    dhclientreleasecmd[strlen(dhclientreleasecmd)] = ' ';
    memcpy(&dhclientcmd[strlen(dhclientcmd)], interface, 4);
    memcpy(&dhclientreleasecmd[strlen(dhclientreleasecmd)], interface, 4);

    return;
}

void get_ip()
{
    struct ifreq ifr;
    strcpy(ifr.ifr_name, interface);
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("error creating socket to get local ip");
        error_handle(-2);
    }
    if ( ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("error getting local ip");
        error_handle(-2);
    }
    memcpy(local_ip, ifr.ifr_addr.sa_data+2, 4);
    memcpy(server_ip, &md5_challenge[4], 4);
    return;
}

void show_usage()
{
    printf("drcom4GDUFS %s      %s\n"
           "run under root privilege\n\n"
           "usage: drcom [OPTION]...\n"
           "usage: drcom -l...\n\n"
           "mandatory arguments to long options are mandatory for short options too\n"
           "  -l --logout                     tell daemon to logout\n"
           "optional arguments:\n"
           "  -d --device=[eth0]              specify which device to use\n"
           "  -c --dhcp-cmd=[dhclient]        specify your own dhcp command\n"
           "  -r --release-cmd=[dhclient -r]  specify your own dhcp release command\n"
           "  -h --help                       show this help\n\n"
           "about drcom4GDUFS:\n"
           "this program is for drcom authentication(with 802.1x), nowadays it has only been tested in the GDUFS school network, compatible with drcom v3.484, developed individually by hunt\n"
           "HUNT Unfortunately No Talent. blog: http://huntxu.blogs.mu\n\n",
           DRCOM_VER, DRCOM_DATE);
    return;
}

void show_version()
{
    printf("drcom4GDUFS(%s) %s\n", DRCOM_VER, DRCOM_DATE);
    return;
}

void init_arguments(int *argc, char ***argv)
{
    int c;
    struct option long_options[] =
    {
        {"help",        no_argument,        0,  'h'},
        {"version",     no_argument,        0,  'v'},
        {"logout",      no_argument,        0,  'l'},
        {"device",      required_argument,  0,  'd'},
        {"dhcp-cmd",    required_argument,  0,  'c'},
        {"release-cmd", required_argument,  0,  'r'},
        {0, 0, 0, 0}
    };

    bzero(interface, 16);
    bzero(dhclientcmd, 20);
    bzero(dhclientreleasecmd, 20);

    while (1) {
        int option_index = 0;
        c = getopt_long((*argc), (*argv), "d:c:r:hlv",
                        long_options, &option_index);

        if (c == -1) break;

        switch (c) {
            case 0:
                break;
            case 'h':
                show_usage();
                exit(EXIT_SUCCESS);
                break;
            case 'v':
                show_version();
                exit(EXIT_SUCCESS);
                break;
            case 'l':
                exit_flag = 1;
                break;
            case 'd':
                strncpy(interface, optarg, 15);
                break;
            case 'c':
                strncpy(dhclientcmd, optarg, 19);
                break;
            case 'r':
                strncpy(dhclientreleasecmd, optarg, 19);
                break;
            case '?':
                if (optopt == 'c' || optopt == 'r'|| optopt == 'd') {
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
}

