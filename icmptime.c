/*
 *   Copyright (c) 2025 Roi

 *	 An ICMP timestamp packet request.
 *   You might need to set `net.ipv4.icmp_echo_ignore_broadcasts` to "0"

 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.

 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.

 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>

#define DIE(p, errcode)    \
	{ fprintf(stderr, "%s\n", p); exit(errcode); }

#define NET_DIE(p, errcode)		\
	{ fprintf(stderr, "%s %s\n", p, gai_strerror(errcode)); exit(errcode); }

struct icmp_tmsp_msg {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint16_t id;
	uint16_t seq;
	uint32_t originate_timestamp;
    uint32_t receive_timestamp;
    uint32_t transmit_timestamp;
};

struct sockaddr_in _sin = {
	.sin_family = AF_INET
};

uint16_t in_checksum(uint16_t *ptr, int n_bytes)
{
	register long sum = 0;
	uint16_t odd_byte;
	register uint16_t ret_checksum;

	while (n_bytes > 1)
	{
		sum += *ptr++;
		n_bytes -= 2;
	}

	if (n_bytes == 1)
	{
		odd_byte = 0;
		*((uint8_t *) & odd_byte) = * (uint8_t *)ptr;
		sum += odd_byte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	ret_checksum = ~sum;

	return ret_checksum;
}

ssize_t broadcast_icmp_timestamp_msg(int sock, const char *host)
{
	struct icmp_tmsp_msg icmp_pkt = { .type = 13, .code = 0, .id = htons(getpid()),
									.seq = htons(12345), .originate_timestamp = htonl(0xDEADBEEF) }; /* With ICMP header included */
	inet_aton(host, &_sin.sin_addr);
	icmp_pkt.checksum = htons(in_checksum((uint16_t *)&icmp_pkt,
								sizeof(icmp_pkt)));

	return sendto(sock, &icmp_pkt, sizeof(icmp_pkt), 0,
				 (struct sockaddr *)&_sin, sizeof(struct sockaddr));
}

int main(int argc, char **argv)
{
	int sock, ret;
	int enable_brd = 1;
	char ascii_host_ip[50];
	struct sockaddr_in *p;
	struct addrinfo *addr_by_host;

	ret = getaddrinfo(argv[1], NULL, NULL, &addr_by_host);
	if (ret)
		NET_DIE("getaddrinfo: ", ret);

	p = (struct sockaddr_in *)(addr_by_host->ai_addr);
	inet_ntop(AF_INET, &p->sin_addr, ascii_host_ip, sizeof(ascii_host_ip));

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); /* IPv4, Raw */
	setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &enable_brd, sizeof(enable_brd));

	ret = broadcast_icmp_timestamp_msg(sock, ascii_host_ip);
	if (ret == -1) {
		freeaddrinfo(addr_by_host);
		DIE("sendto: ", errno);
	}
	
	printf("Destination: %s\nNumber of octets sent: %d\n", ascii_host_ip, ret);

	freeaddrinfo(addr_by_host);
	return 0;
}
