/* Terrible mDNS responder
 *
 * Copyright © 2021 Sergey Bugaev <bugaevc@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>

#include "terrible-mdns.h"

int announce(uint32_t ttl) {
    struct ifaddrs *ifaddrs;
    int rc = getifaddrs(&ifaddrs);
    if (rc < 0) {
        perror("getifaddrs");
        return -1;
    }

    unsigned char buffer[512];

    struct packet packet = {
        .id = 0,
        .flags = htons(0x8400),
        .query_count = 0,
        .answer_count = 0, // to be filled
        .authority_count = 0,
        .additional_count = 0,
    };

    unsigned char *ptr = buffer + sizeof(packet);

    uint16_t answer_count = 0;
    size_t hostname_len = strlen(mdns_hostname);
    for (struct ifaddrs *ifaddr = ifaddrs; ifaddr; ifaddr = ifaddr->ifa_next) {
        if (!ifaddr->ifa_addr || !ifaddr->ifa_name) {
            continue;
        }
        const struct sockaddr *addr = ifaddr->ifa_addr;
        if (addr->sa_family != AF_INET) {
            continue;
        }
        const struct sockaddr_in *addr_in = (const struct sockaddr_in *) addr;
        if (addr_in->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
            continue;
        }

        size_t record_length = 1 + hostname_len + 1 + strlen(local) + 1 + 2 + 2 + 4 + 2 + 4;
        if (ptr + record_length > buffer + sizeof(buffer)) {
            // TODO: set TC.
            break;
        }

        *ptr++ = hostname_len;
        memcpy(ptr, mdns_hostname, hostname_len);
        ptr += hostname_len;
        *ptr++ = strlen(local);
        memcpy(ptr, local, strlen(local));
        ptr += strlen(local);
        *ptr++ = 0;
        uint16_t type = htons(1);
        memcpy(ptr, &type, 2);
        ptr += 2;
        uint16_t class = htons(0x8001);
        memcpy(ptr, &class, 2);
        ptr += 2;
        uint32_t ttl_no = htonl(ttl);
        memcpy(ptr, &ttl_no, 4);
        ptr += 4;
        uint16_t len = htons(4);
        memcpy(ptr, &len, 2);
        ptr += 2;
        memcpy(ptr, &addr_in->sin_addr, 4);
        ptr += 4;
        answer_count++;
    }
    freeifaddrs(ifaddrs);
    packet.answer_count = htons(answer_count);

    memcpy(buffer, &packet, sizeof(packet));

    struct sockaddr_in dest_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(MDNS_PORT),
        .sin_addr = MDNS_MULTICAST_ADDR,
    };

    return sendto(socket_fd, buffer, ptr - buffer, 0,
                  (const struct sockaddr *) &dest_addr,
                  sizeof(dest_addr)
                 );
}
