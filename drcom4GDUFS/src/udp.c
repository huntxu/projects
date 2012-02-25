#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iconv.h>

extern const u_char *server_ip;
extern const u_char *local_ip;
extern const u_char *local_mac;
extern const u_char *username;
extern const int username_length;
extern const u_char *md5_digest;

static struct sockaddr_in server_addr;
static struct sockaddr_in local_addr;
static int sockfd;
static int len;

static u_char udp_keepalive_buffer[0x26];

static int code_convert(char *from_charset, char *to_charset, char *inbuf, size_t inlen, char *outbuf, size_t outlen)
{
    iconv_t cd;
    cd = iconv_open(to_charset, from_charset);
    if (cd ==0) return -1;

    memset(outbuf, 0 , outlen);

    if (iconv(cd, &inbuf, &inlen, &outbuf, &outlen) == -1) return -1;

    iconv_close(cd);
    return 0;
}

static void udp_keepalive(int sig)
{
    if ( sendto(sockfd, udp_keepalive_buffer, 0x26, 0,
                (struct sockaddr *)&server_addr, len) == -1) {
        perror("error sending keepalive udp packet");
    }
    alarm(31);
    return;
}

static int send_first_udp_packet()
{
    u_char buf[8]={0x07, 0x01, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00};
    if ( sendto(sockfd, buf, 8, 0, (struct sockaddr *)&server_addr, len)
            == -1) {
        perror("error sending first udp packet");
        return -1;
    }
    return 0;
}

static int send_second_udp_packet()
{
    u_char head[0x06] = {0x07, 0x00, 0xf4, 0x00, 0x03, 0x0b};
    u_char string1[0x04] = {0x01, 0x02, 0x00, 0x00};
    u_char solid[0x08]
        = {0xc7, 0x2f, 0x31, 0x01, 0x7e, 0x00, 0x00, 0x00};
    u_char trailer[0x96] = {0x00, 0x94, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x28, 0x0a, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x20, 0x50, 0x61, 0x63, 0x6b, 0x20, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    u_char imp[0x04];

    u_char in_buf[0x12];
    u_char out_buf[0xf4];
    int out_length = 0;

    u_char hostname[0x10];
    int hostname_length;
    if (gethostname(hostname, 0x10) == -1) {
        perror("error getting hostname");
        return -1;
    }
    hostname_length = strlen(hostname);
    int zero_length = 0x3e - username_length - hostname_length;

    if ( recvfrom(sockfd, in_buf, sizeof(in_buf), 0,
                  (struct sockaddr *)&local_addr, &len) == -1) {
        perror("error receiving first udp packet");
        return -1;
    }

    memcpy(out_buf, head, 0x06);
    out_length += 0x06;
    memcpy(&out_buf[out_length], &local_mac, 0x06);
    out_length += 0x06;
    memcpy(&out_buf[out_length], &local_ip, 0x04);
    out_length += 0x04;
    memcpy(&out_buf[out_length], string1, 0x04);
    out_length += 0x04;
    memcpy(&out_buf[out_length], in_buf+0x08, 0x04);
    out_length += 0x04;
    memcpy(&out_buf[out_length], solid, 0x08);
    out_length += 0x08;
    memcpy(&out_buf[out_length], &username, username_length);
    out_length += username_length;
    memcpy(&out_buf[out_length], &hostname, hostname_length);
    out_length += hostname_length;
    bzero(&out_buf[out_length], zero_length);
    out_length += zero_length;
    memcpy(&out_buf[out_length], trailer, 0x96);
    out_length += 0x96;
    if (out_length != 0xf4) {
        perror("error while constructing second udp packet to send");
        return -1;
    }

    u_int *p=(u_int *) out_buf;
    u_int a=0;
    int i;
    for (i=0; i<= 0x3c; i++) {
        a ^= *p;
        p++;
    }
    a *= 0x12c4b7e;
    memcpy(imp, &a, 0x04);
    memcpy(&udp_keepalive_buffer[1], imp, 0x04);
    memcpy(&out_buf[0x18], imp, 0x04);
    out_buf[0x1c] = 0x00;

    if ( sendto(sockfd, out_buf, 0xf4, 0,
                (struct sockaddr *)&server_addr, len) == -1) {
        perror("error sending second udp packet");
        return -1;
    }
    return 0;
}

static int recv_two_udp_packet()
{
    u_char str_for_keepalive[0x10];
    u_char in_buf[0xff];

    if ( recvfrom(sockfd, in_buf, sizeof(in_buf), 0,
                  (struct sockaddr *)&local_addr, &len) == -1) {
        perror("error receiving second udp packet");
        return -1;
    }
    u_int i;
    for (i=0; i<0x10; i++) {
        str_for_keepalive[i] = ((in_buf[0x10+i])<<(i%8))
                               + ((in_buf[0x10+i])>>(8-(i%8)));
    }
    memcpy(&udp_keepalive_buffer[0x14], str_for_keepalive, 0x10);

    int recvbytes = recvfrom(sockfd, in_buf, sizeof(in_buf), 0,
                            (struct sockaddr *)&local_addr, &len);

    if ( recvbytes == -1 ) {
        perror("error receiving message udp packet");
        return -1;
    }

    char info_str[0xff] = {0};
    if ( code_convert("gb2312", "utf-8",
                      &in_buf[4], recvbytes-4,
                      info_str, 0xff) == -1) {
        perror("error while converting server msg charset");
        return -1;
    }
    fprintf(stdout, "server info:\n    %s\n", info_str);

    return 0;
}

int init_udp()
{
    len = sizeof(struct sockaddr_in);

    bzero(&server_addr, len);
    bzero(&local_addr, len);

    server_addr.sin_family = AF_INET;
    local_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(0xf000);
    local_addr.sin_port = htons(0xf000);
    memcpy(&server_addr.sin_addr, &server_ip, 4);
    memcpy(&local_addr.sin_addr, &local_ip, 4);
   
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if ( sockfd < 0 ) {
        perror("error creating socket for udp communication");
        return -1;
    }

    if ( bind(sockfd, (struct sockaddr *)&local_addr, len) == -1 ) {
        perror("error binding socket");
        return -1;
    }

    if ( send_first_udp_packet() == -1 ) {
        return -1;
    }

    if ( send_second_udp_packet() == -1 ) {
        return -1;
    }

    if ( recv_two_udp_packet() == -1 ) {
        return -1;
    }
    udp_keepalive_buffer[0]=0xff;
    memcpy(&udp_keepalive_buffer[5], (&md5_digest+1), 0x0c);
    bzero(&udp_keepalive_buffer[0x11], 3);
    udp_keepalive_buffer[0x24] = 0x02;
    udp_keepalive_buffer[0x25] = 0x16;

    if ( sendto(sockfd, udp_keepalive_buffer, 0x26, 0,
                (struct sockaddr *)&server_addr, len) == -1) {
        perror("error sending first keepalive udp packet");
        return -1;
    }
    signal(SIGALRM, udp_keepalive);

    return 0;
}

