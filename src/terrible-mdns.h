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

#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>

#define MDNS_PORT 5353
#define MDNS_MULTICAST_ADDR { htonl(0xe00000fb) } // 224.0.0.251

struct packet {
    uint16_t id;
    uint16_t flags;
    uint16_t query_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_count;
};

int parse_request(const unsigned char *data, size_t size);
int announce(uint32_t ttl);

extern int socket_fd;
extern char mdns_hostname[256];
extern const char *local;

