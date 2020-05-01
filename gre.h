#ifndef GRE_H
#define GRE_H

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

/* OS-dependant macros */
#include <sys/param.h>

#ifdef __linux__
#define uint32_t u_int32_t
#endif 



#define GRE_MAXLEN 16

#define ETHTYPE_IPv4 0x0800 //network order, little endian
#define ETHTYPE_IPv6 0x86DD
#define ETHTYPE_ETH 0x6558

#define HASKEY_MASK (0x00 | 1 << 5)
#define TYPE_BYTE 2

extern int af;

struct GRE_Header { /* at this state it's 16 bytes long */
        unsigned hasChksum: 1;
        unsigned hasRoute_UNUSED: 1;
        unsigned hasKey: 1;
        unsigned strict_source_UNUSED: 1;
        unsigned reserved0: 9;
        unsigned ver: 3;        /* this must be 0 */
        unsigned proto_type: 16;
        unsigned checksum: 16;
        unsigned reserved1: 16;
        unsigned key: 32;
        unsigned seqNum_UNUSED: 32;
}__attribute__((packed));


enum exitCodes {
        OK = 0,
        INVALID_ARGS = 1,
        BAD_PORT = 2,
};

enum tunnelType {
        TYPE_ETHER = 0,
        TYPE_IP = 1,
};

ssize_t
gre_encapsulate(u_char *, u_char *, ssize_t, bool, uint32_t, enum tunnelType);




#endif