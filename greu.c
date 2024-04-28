#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/queue.h>
/* include cdefs for non-standard GCC attribute extensions */
#include <sys/cdefs.h>

#include <stdio.h>
#include <stdarg.h>
#include <err.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <stdint.h>

#include <netdb.h>
#include <arpa/inet.h>

#include <fcntl.h>

#include <err.h>
#include <errno.h>
#include <event.h>

#include "gre.h"
#include "rc4.h"

u_char *encryption_key; // should be 16 bytes
#define KEYLEN 16

#define IP_MAX 40 /* IPv6 has 39 max characters + NULL */
#define MTU 1500

/* for portability with glibc test macros */
#define _BSD_SOURCE

/* tunnel entry for each tunnel */
struct tunnel {
	TAILQ_ENTRY(tunnel) entry;
	int fd;
	struct event    ev;
	enum tunnelType type;
	bool hasKey;
	uint32_t key;
};

TAILQ_HEAD(tunnel_list, tunnel);

struct tunnel_list tunnels = TAILQ_HEAD_INITIALIZER(tunnels);

bool daemonizeFlag, listenFlag;
int af = AF_INET; /* default IPv4 */
char *port = "4754"; /* default port according to RFC RFC 8086*/
char src_port[NI_MAXSERV];
char bindHost[IP_MAX];

int udpSock;
struct sockaddr svr_sockaddr;

/*
 * possibly useful functions
 */
void
hexdump(const void *d, size_t datalen)
{
    const uint8_t *data = d;
    size_t i, j = 0;

    for (i = 0; i < datalen; i += j) {
	printf("%4zu: ", i);
	for (j = 0; j < 16 && i+j < datalen; j++)
	    printf("%02x ", data[i + j]);
	while (j++ < 16)
	    printf("   ");
	printf("|");
	for (j = 0; j < 16 && i+j < datalen; j++)
	    putchar(isprint(data[i + j]) ? data[i + j] : '.');
	printf("|\n");
    }
}

void
msginfo(const struct sockaddr_storage *ss, socklen_t sslen, size_t len)
{
    char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV]; //XXX NI_MAX* not portable 
    int error;

    error = getnameinfo((const struct sockaddr *)ss, sslen,
	hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
	NI_NUMERICHOST | NI_NUMERICSERV);
    if (error != 0) {
	warnx("msginfo: %s", gai_strerror(error));
	return;
    }

    fprintf(stderr, "host %s port %s bytes %zu\n", hbuf, sbuf, len);
}


#ifdef BSD
__dead 
#endif
void
usage(void) 
{
	char *usage_msg = "usage: greu [-46d] [-l address] [-p port]\n\
\t    [-e /dev/tapX[@key]] [-i /dev/tunX[@key]] [-K ENCRYPTION_KEY]\n\
\t    server [port]\n";
	fprintf(stderr, "%s", usage_msg);
	exit(INVALID_ARGS);
}


static void
udp_recv(int fd, short revents, void *addr)
{
	fprintf(stderr, "======== udp_recv called! ==========\n");
	u_char encrypted_buf[MTU] = {0};
	u_char buf[MTU] = {0};
	// ssize_t rlen = read(fd, buf, MTU);

	struct sockaddr from;
	socklen_t fromLen = sizeof(struct sockaddr);

	ssize_t rlen = recvfrom(fd, encrypted_buf, MTU, 0, &from, &fromLen);
	// decrypt packet
	RC4_drop(encryption_key, encrypted_buf, buf, KEYLEN, rlen);

	msginfo((struct sockaddr_storage *) &from, fromLen, rlen);
	hexdump(buf, rlen);

	//TODO: write back into interface after parsing tunnel
	uint16_t type = 0;
	memcpy(&type, &buf[TYPE_BYTE], 2);
	type = ntohs(type); //swap network order, 16 bit
	
	fprintf(stderr, "ethertype: %04x\n", type);

	uint32_t key;
	int strippedLen = rlen - 4;

	if (buf[0] & HASKEY_MASK) {
	    memcpy(&key, buf + 4, 4); //byte 4-7 would be key if no checksum
	    key = ntohl(key);
	    fprintf(stderr, "key present: %u\n", key);
	}

	fprintf(stderr, "strippedLen: %d\n", strippedLen);
	struct tunnel *tunnel_entry;

	if (type == ETHTYPE_IPv4 || type == ETHTYPE_IPv6) {
		
		hexdump(buf + 4, strippedLen);
		TAILQ_FOREACH(tunnel_entry, &tunnels, entry) {
		    if (tunnel_entry->type == TYPE_IP) {
		    	fprintf(stderr, "sending to tun devices..\n");
			if (tunnel_entry->hasKey == false) {
			    //HACK skip 4 bytes cos GRE header
			    write(tunnel_entry->fd, buf + 4, strippedLen);  
			} else if (tunnel_entry->key == key) { //handle key
			    write(tunnel_entry->fd, buf + 8, strippedLen);  
			}
		    }
		}
	} else if (type == ETHTYPE_ETH) {
		
		hexdump(buf + 4, strippedLen);
		TAILQ_FOREACH(tunnel_entry, &tunnels, entry) {
		    if (tunnel_entry->type == TYPE_ETHER) {
		    	fprintf(stderr, "sending to tap devices..\n");
			if (tunnel_entry->hasKey == false) {
			    //HACK skip 4 bytes cos GRE header
			    write(tunnel_entry->fd, buf + 4, strippedLen);  
			} else if (tunnel_entry->key == key) { //handle key
			    write(tunnel_entry->fd, buf + 8, strippedLen);  
			}
		    }
		    
		}
	}

	fprintf(stderr, "====================================\n");

}


static void
tunnel_recv(int fd, short revents, void *tunnel_arg)
{       
	struct tunnel *tunnel = (struct tunnel *) tunnel_arg;

	fprintf(stderr, "tunnel_recv called! tunnel type: ");
	if (tunnel->type == TYPE_ETHER) {
		fprintf(stderr, "Ethernet\n");
	} else if (tunnel->type == TYPE_IP) {
		fprintf(stderr, "IP\n");
	}
	/* very important to zero-fill buffer, otherwise mem leak can occur */
	u_char buf[MTU] = {0}; 
	// FILE *stream = fdopen(fd, "r");
	// size_t rlen = fread(buf, 1, MTU, stream);
	ssize_t rlen = read(fd, buf, MTU);
	hexdump(buf, rlen);

	/* encapsulate into GRE */
	u_char grePkt[rlen + GRE_MAXLEN];
	memset(grePkt, 0, rlen + GRE_MAXLEN);
	ssize_t plen;
	if (tunnel->hasKey) {
	    plen = gre_encapsulate(grePkt, buf, rlen, 
			true, tunnel->key, tunnel->type);
	} else {
	    plen = gre_encapsulate(grePkt, buf, rlen, 
			false, tunnel->key, tunnel->type);
	}
	

	fprintf(stderr, "GRE packet:\n");
	hexdump(grePkt, plen);

	// encrypt packet before sending over network
	u_char encrypted_pkt[rlen + GRE_MAXLEN];
	RC4_drop(encryption_key, grePkt, encrypted_pkt, KEYLEN, plen);


	/* send this to the udp socket */
	if (sendto(udpSock, encrypted_pkt, plen, 0, &svr_sockaddr, 
		sizeof(struct sockaddr)) < 0) {
		errx(1, "[tunnel_recv] sending udp packet failed");
	}

}

void
udp_connect(char *host)
{       

	

	struct addrinfo hints, *res;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_DGRAM;

	error = getaddrinfo(host, port, &hints, &res);

	if (error)
		errx(1, "%s", gai_strerror(error));

	svr_sockaddr = *(res->ai_addr);

	if ((udpSock = socket(res->ai_family, SOCK_DGRAM | SOCK_NONBLOCK, 0)
		) < 0) {
		errx(1, "sock create failed");
	}


	/* bind on a local port to specify UDP source port */
	long srcportNum = strtol(src_port, (char **) NULL, 10);
	if (srcportNum < 1 || srcportNum > 65535)
		errx(1, "invalid source port.");

	struct sockaddr_in src_in;
	memset(&src_in, 0, sizeof(src_in));
	src_in.sin_family = af;
	/* TODO: handle local addr */
	if (!listenFlag) {
		src_in.sin_addr.s_addr = htonl(INADDR_ANY);
	} else {
		// src_in.sin_addr.s_addr = 
		fprintf(stderr, "binding to host: %s\n", bindHost);
		inet_pton(af, bindHost, &src_in.sin_addr.s_addr);
	}
	src_in.sin_port = htons(srcportNum);
	

	fprintf(stderr, "source port: %ld\n", srcportNum);
	if (bind(udpSock, (struct sockaddr *) &src_in, 
			sizeof(struct sockaddr_in)) < 0)
		errx(1, "binding host/source port failed");

	if (setsockopt(udpSock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
	    errx(1, "binding host/source port failed");

	struct event *ev = malloc(sizeof(struct event));
	event_set(ev, udpSock, EV_READ|EV_PERSIST, udp_recv, 
		&res->ai_addr);
	event_add(ev, NULL);
	
}

/* get the content of the GRE Extension key given a dev@key string 
 * returns -1 if there's no keys
 */
long
get_key(const char *dev)
{
    int keyIndex = -1;
    for (int i = 0; i < strlen(dev); i++) {
	if (dev[i] == '@') {
	    keyIndex = i + 1;
	    break;
	}
    }

    if (keyIndex == -1) { //no key
	return -1;
    }

    long key = strtol(dev + keyIndex, (char **)NULL, 10);
    fprintf(stderr, "[get_key] key: %ld\n", key);
    return key;
}


/* bind to tunnel device */
void
bind_dev(struct tunnel_list *tunnels, const char *path, enum tunnelType type)
{       
	long key = get_key(path);
	char pathCpy[strlen(path) + 1];
	memset(&pathCpy, 0, sizeof(pathCpy));

	strncpy(pathCpy, path, strlen(path));
	char *path_without_key = strtok(pathCpy, "@");
	fprintf(stderr, "[bind dev] %s\n", pathCpy);
	#ifdef BSD
	fprintf(stderr, "BSD detected\n");
	int fd = open(path_without_key, O_RDWR | O_NONBLOCK);
	#else
	#include <linux/if.h>
	#include <linux/if_tun.h>
	#include <sys/ioctl.h>

	char *clonedev = "/dev/net/tun";

	int fd = open(clonedev, O_RDWR | O_NONBLOCK);
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	if (type == TYPE_ETHER)
	    ifr.ifr_flags = IFF_TAP | IFF_NO_PI; /* no packet info added */
	else if (type == TYPE_IP)
	    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	strncpy(ifr.ifr_name, path_without_key, IFNAMSIZ);
	if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0 ) {
		close(fd);
		errx(1, "error tunnel ioctl: %s", strerror(errno));
	}

	#endif


	if (fd < 0) {
		errx(1, "error openning tunnel: %s", strerror(errno));
	}


	struct tunnel *tunnel_entry = malloc(sizeof(struct tunnel));
	tunnel_entry->type = type;
	tunnel_entry->fd = fd;

	if (key == -1) {
	    tunnel_entry->hasKey = false; /* TODO: handle keys! */
	} else {
	    tunnel_entry->hasKey = true;
	    tunnel_entry->key = (uint32_t) key;
	}

	TAILQ_INSERT_HEAD(tunnels, tunnel_entry, entry);

	if (TAILQ_EMPTY(tunnels)) {
	    errx(1, "TAILQ empty");
	}

}


/* 
 * greu is a program that implements the GRE-in-UDP encapsulation described
 * in RFC 8086. The default port is 4754.
 * 
 * It will connect to a server and establish a tunnel over a tap/tun 
 * interface.
 */
int 
main (int argc, char *argv[])
{
	if (argc < 2) {
		usage();
	}

	int ch;
	// ip4Flag, ip4Flag, daemonizeFlag, listenFlag = false;
	// int port;
	daemonizeFlag = false;
	listenFlag = false;
	encryption_key = NULL;
	
	/* by default source port is dest port (4754), and bind on any */
	// strncpy(src_port, port, sizeof(src_port));
	// strncpy(bindHost, "0.0.0.0", sizeof(bindHost));

	while ((ch = getopt(argc, argv, "46dl:p:e:i:K:")) != -1) {
		switch (ch) {      
		case '4':       
			af = AF_INET;
			break;
		case '6':
			af = AF_INET6;
			break;

		case 'd':
			daemonizeFlag = true;
			break;

		case 'l':
			listenFlag = true;
			strncpy(bindHost, optarg, IP_MAX);
			break;
		case 'p':
			strncpy(src_port, optarg, sizeof(src_port));
			break;

		case 'e':
			printf("ethernet tunnel: %s\n", optarg);
			bind_dev(&tunnels, optarg, TYPE_ETHER);
			break;
		case 'i':
			printf("internet tunnel: %s\n", optarg);
			bind_dev(&tunnels, optarg, TYPE_IP);
			break;
		case 'K':
			encryption_key = (u_char*) malloc(KEYLEN);
			memcpy(encryption_key, optarg, KEYLEN);
			break;

		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (encryption_key == NULL) {
		// gen random key
		encryption_key = malloc(KEYLEN);
		for (int i = 0; i < KEYLEN; i++) {
			encryption_key[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0987654321"[random () % 36];
		}
		fprintf(stderr, "generated random key for -K on client side: %s\n", encryption_key);

	}

	
	if (daemonizeFlag) {
		fprintf(stderr, "daemonizing..\n");
		fflush(NULL);
	    daemon(1, 1); //no chdir, no close fds
	}

	event_init();

	if (TAILQ_EMPTY(&tunnels)) {
	    fprintf(stderr, 
		    "must configure at least one Ethernet or IP tunnel.\n");
	    usage();
	}


	char *server = argv[0];

	if (argc == 2) { /* if there is a port argument */
		char *end;
		int portNum = strtol(argv[1], &end, 10);
		/* end != NULL means there's an error in strtol */
		if ((argv[1][0] == '\0' || *end != '\0') || 
		    (portNum < 1 || portNum > 65535)) { 
		    fprintf(stderr, "Port is invalid. Must be a number between\
		1 and 65535 inclusive\n");
		    exit(BAD_PORT);
		}
		port = argv[1];
		//src port should equal to dst port by default

	}
	strncpy(src_port, port, sizeof(src_port));
	
	// //remaining arguments
	// for (int i = 0; i < argc; i++) {
	//     printf("%i: %s\n", i, argv[i]);
	//     server 
	// }

	fprintf(stderr, "server: %s:%s\n", server, port);
	udp_connect(server);


	struct tunnel *tunnel_entry;
	TAILQ_FOREACH(tunnel_entry, &tunnels, entry) {
		fprintf(stderr, "adding event for tunnel fd: %d\n", tunnel_entry->fd);
		// event_set(&e->ev, EVENT_FD(&e->ev), EV_READ|EV_PERSIST, tunnel_recv, NULL);
		event_set(&tunnel_entry->ev, tunnel_entry->fd, EV_READ|EV_PERSIST, tunnel_recv, tunnel_entry);
		int retcode = event_add(&tunnel_entry->ev, NULL);
		if (retcode) {
			fprintf(stderr, "event_add ret code: (%i)\n", retcode);
			errx(1, "event_add errno: (%i) %s", errno, strerror(errno));
		}
		// event_add(&e->ev, NULL);
	}	


	if (TAILQ_EMPTY(&tunnels)) {
	    errx(1, "TAILQ empty");
	}
	int retcode = event_dispatch();

	// The callback returns 1 when no events are registered any more
	if (retcode != 0) {
		fprintf(stderr, "event_dispatch retval: (%i)\n", retcode);

		// errx(1, "errno: (%i) %s", errno, strerror(errno));
		
	}
	fprintf(stderr, "Exiting..\n");
	return 0;
}

