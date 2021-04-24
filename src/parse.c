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

#include <stdint.h>
#include <string.h>

#include "terrible-mdns.h"

static int compare(const char *s1, const char *ptr, size_t length) {
    size_t s1_len = strlen(s1);
    if (s1_len != length) {
        return 0;
    }
    return strncmp(s1, ptr, length) == 0;
}

static int parse_query(const unsigned char **ptr, const unsigned char *end) {
    size_t index = 0;
    int match = 1;
    while (1) {
        if (*ptr >= end) {
            return -1;
        }
        unsigned char len = *(*ptr)++;
        if (len == 0) {
            break;
        }
        if (len & 0xc0) {
            // Assume it doesn't match.
            (*ptr)++;
            match = 0;
            break;
        }
        if (*ptr + len >= end) {
            // Bad length.
            return -1;
        }
        switch (index++) {
        case 0:
            if (!compare(mdns_hostname, (const char *) *ptr, len)) {
                match = 0;
            }
            break;
        case 1:
            if (!compare(local, (const char *) *ptr, len)) {
                match = 0;
            }
            break;
        default:
            match = 0;
            break;
        }
        *ptr += len;
    }
    if (index != 2) {
        match = 0;
    }
    if (*ptr + 4 > end) {
        return -1;
    }
    struct {
        uint16_t type;
        uint16_t class;
    } no;
    memcpy(&no, *ptr, 4);
    *ptr += 4;
    uint16_t type = ntohs(no.type);
    uint16_t class = ntohs(no.class);
    if (type != 1 && type != 28) {
        match = 0;
    }
    if (class != 1 && class != 0x8001) {
        match = 0;
    }
    return match;
}

int parse_request(const unsigned char *data, size_t size) {
    if (size < sizeof(struct packet)) {
        return -1;
    }

    const struct packet *packet_no = (const struct packet *) data;
    struct packet packet = {
        .id = ntohs(packet_no->id),
        .flags = ntohs(packet_no->flags),
        .query_count = ntohs(packet_no->query_count),
        .answer_count = ntohs(packet_no->answer_count),
        .authority_count = ntohs(packet_no->authority_count),
        .additional_count = ntohs(packet_no->additional_count),
    };
    if (packet.flags & 0xf800) {
        // This is not a query.
        return 0;
    }
    if (packet.flags & 0x0200) {
        // The query was truncated.
        // TODO: How should we handle this?
        return 0;
    }
    // TODO: All the other bits.
    if (packet.query_count == 0) {
        // There's nothing we can answer.
        return 0;
    }

    const unsigned char *ptr = data + sizeof(struct packet);
    int should_respond = 0;
    for (uint16_t query_index = 0; query_index < packet.query_count; query_index++) {
        int r = parse_query(&ptr, data + size);
        switch (r) {
        case -1:
            return -1;
        case 0:
            break;
        case 1:
            should_respond = 1;
            break;
        }
    }

    return should_respond;
}
