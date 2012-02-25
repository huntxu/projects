#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>

#define DRCOM_VER "1.1"
#define DRCOM_DATE "2009-11-19"

/* default snap length */
#define SNAP_LEN 1518

#define AUTH_HLEN 0x04
struct auth_header {
    /*     version       : always 0x01                          *
     *      type         : 0x00 eap_packet, 0x02 logoff         *
     * send packet length: EAP_LOGOFF -- 0x0000                 *
     *                     EAP_RESPONSE_IDENTITY -- 0x0019      *
     *                     EAP_RESPONSE_MD5_CHALLENGE -- 0x002a */
    u_char eapol_version;
    u_char eapol_type;
    u_short eapol_length;
};

#define EAP_HLEN 0x05
struct eap_header {
    /*   code   : 0x01: request                             *
     *            0x02: response                            *
     *            0x03: success                             *
     *            0x04: failure                             *
     *  length  : same with eapol_length if NEED_EAP_HEADER *
     *   type   : 0x01: identity                            *
     *            0x02: notification                        *
     *            0x04: md5_challenge                       */
    u_char eap_code;
    u_char eap_id;
    u_short eap_length;
    /* actually success&failure don't have the eap_type char*
     * but it doesn't matter                                */
    u_char eap_type;
};

#define EAP_CODE_REQUEST 0x01
#define EAP_CODE_SUCCESS 0x03
#define EAP_CODE_FAILURE 0x04
#define EAP_REQUEST_IDENTITY 0x01
#define EAP_REQUEST_NOTIFICATION 0x02
#define EAP_REQUEST_MD5_CHALLENGE 0x04

#define NEED_EAP_HEADER 16
#define NEED_USERNAME 8
#define NEED_MD5 4
#define NEED_TRAILER1 2
#define NEED_TRAILER2 1

enum EAPSendType {
/*      what's that num means?
 * EAP_LOGOFF:
 *  NEED_TRAIL1
 * EAP_RESPONSE_IDENTITY:
 *  NEED_EAP_HEADER | NEED_USERNAME | NEED_TRAIL1 | NEED_TRAIL2
 * EAP_RESPONSE_MD5_CHALLENGE:
 *  NEED_EAP_HEADER | NEED_MD5 | NEED_USERNAME | NEED_TRAIL1 | NEED_TRAIL2
 */
    EAPOL_START,
    EAPOL_LOGOFF                = 2,
    EAP_RESPONSE_IDENTITY       = 27,
    EAP_RESPONSE_MD5_CHALLENGE  = 31
};

enum STATE {
    STARTED,
    IDENTIFIED,
    AUTHED,
    ONLINE
};

void send_eap_packet(enum EAPSendType send_type);
void get_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void get_ip();
void show_usage();
void init_arguments(int *argc, char ***argv);

void error_handle(int sig);
void init_device();
void init_info();

int init_udp();
void md5digest();
void init_daemon();

