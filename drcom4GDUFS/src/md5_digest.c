#include <string.h>
#include <sys/types.h>
#include "md5.h"

extern const int username_length;
extern const int password_length;
extern const u_char *username;
extern const u_char *password;
extern const u_char *md5_challenge;
extern const u_char *md5_digest;
static u_char pwd[64];
static int pwd_length;

void md5digest()
{
    pwd[0] = 0x02;
    pwd_length += 0x01;
    memcpy(&pwd[pwd_length], &password, password_length);
    pwd_length += password_length;
    memcpy(&pwd[pwd_length], &md5_challenge, 0x10);
    pwd_length += 0x10;
    bzero(&pwd[pwd_length], 4);
    pwd_length += 0x04;
    pwd[pwd_length] = 0x80;
    pwd_length += 0x01;
    bzero(&pwd[pwd_length], 56-pwd_length);
    pwd[56] = (u_char) ((password_length+11)<<3);
    bzero(&pwd[57], 7);

    md5_state_t ctx;
    md5_init(&ctx);
    md5_append(&ctx, pwd, username_length+password_length+6);
    md5_finish(&ctx, (md5_byte_t *)(&md5_digest));
    return;
}
