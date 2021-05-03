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

#include <unistd.h>
#include <stdio.h>
#include <error.h>
#include <errno.h>
#include <signal.h>

#include "terrible-mdns.h"

char mdns_hostname[256];
const char *local = "local";
int socket_fd = -1;

void goodbye() {
    announce(0);
}

void signal_handler(int signo) {
    exit(1);
}

int main(int argc, const char *argv[]) {
    int rc = gethostname(mdns_hostname, sizeof(mdns_hostname));
    if (rc < 0) {
        error(1, errno, "failed to get host name");
    }
    mdns_hostname[255] = 0;

    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        error(1, errno, "failed to create UDP socket");
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(MDNS_PORT),
        .sin_addr = { htonl(INADDR_ANY) },
    };
    rc = bind(socket_fd, (const struct sockaddr *) &addr, sizeof(addr));
    if (rc < 0) {
        error(1, errno, "failed to bind to 0.0.0.0:%d", MDNS_PORT);
    }

    unsigned char zero = 0;
    rc = setsockopt(socket_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &zero, 1);
    if (rc < 0) {
        error(0, errno, "failed to disable multicast loopback");
    }
    struct ip_mreq mreq = {
        .imr_multiaddr = MDNS_MULTICAST_ADDR,
        .imr_interface = { htonl(INADDR_ANY) },
    };
    rc = setsockopt(socket_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    if (rc < 0) {
        error(1, errno, "failed to join the multicast group");
    }

    rc = announce(120);
    if (rc < 0) {
        error(0, errno, "failed to announce");
    }

    atexit(goodbye);
    signal(SIGTERM, signal_handler);

    while (1) {
        {
            unsigned char buffer[512];
            rc = recv(socket_fd, buffer, sizeof(buffer), 0);
            if (rc < 0) {
                error(1, errno, "recv");
            }
            rc = parse_request(buffer, rc);
            if (rc != 1) {
                continue;
            }
        }
        rc = announce(120);
        if (rc < 0) {
            error(0, errno, "failed to send the response");
        }
    }
}
