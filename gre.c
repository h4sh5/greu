#include "gre.h"

#include <ctype.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>


#define ETHTYPE_IPv4 0x0800 //network order, little endian
#define ETHTYPE_IPv6 0x86DD
#define ETHTYPE_ETH 0x6558

/*
 * Destination buffer has to be sufficient size
 */
ssize_t
gre_encapsulate(u_char *dstBuf, u_char *srcBuf, ssize_t srcLen, bool hasKey, 
		uint32_t key,
          	enum tunnelType type)
{	
	
        // memcpy(dstBuf, srcBuf, srcLen);
        // dstBuf = srcBuf + srcLen;

	ssize_t pktLen = 0;

        struct GRE_Header header;
        memset(&header, 0, sizeof(struct GRE_Header));
        if (hasKey == 0)
                header.hasKey = 0;
        else {
        	header.hasKey = 1;
                header.key = key;
                u_char firstByte = 1 << 2;
                memcpy(dstBuf, &firstByte, 1); //set key flag

                uint32_t swappedKey = htonl(key);
                memcpy(dstBuf + 8, &swappedKey, 4);
                pktLen += 4;
        }

        if (type == TYPE_IP) {
        	af == AF_INET6 ? (header.proto_type = ETHTYPE_IPv6) : 
        		(header.proto_type = ETHTYPE_IPv4);
        } else {
        	header.proto_type = ETHTYPE_ETH;
        }

        uint16_t proto_type = htons(header.proto_type); //network byte
        
        // memcpy(dstBuf, &header, GRE_MAXLEN);
        memcpy(dstBuf, &header, 2);
        memcpy(dstBuf + 2, &proto_type, 2);
        pktLen += 4;

        printf("sizeof GRE_Header: %lu\n", pktLen);
        memcpy(&dstBuf[pktLen], srcBuf, srcLen);

        return pktLen + srcLen;

        // memcpy(dstBuf, &header->checksum, 2);
        // memcpy(dstBuf + 8, &swappedKey, 4);

}

