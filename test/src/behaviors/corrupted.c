/*
 * This file is part of the GNU Practical Dynamic Group Communication (GPDGC)
 * Copyright (C) 2020, Rütti Olivier <olivier.rutti@opengroupware.ch>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#define _GNU_SOURCE

#include <errno.h>

#include <common.h>
#include <message.h>
#include <process.h>
#include <server.h>

typedef struct
{
    void *content;
    size_t size;
} gpdgc_content;

void *gpdgc_randomly_modify_message(void *buffer, 
        size_t buffer_size, size_t *size)
{
    *size = 0;

    void *result = malloc(buffer_size);
    memcpy(result, buffer, buffer_size);
    if (result != NULL)
    {
        *size = buffer_size;
        for (int nb_changes = rand() % buffer_size; nb_changes>0; nb_changes--)
        {
            int index_to_change = rand() % buffer_size;
            char *byte_to_change = ((char *)result) + index_to_change;
            *byte_to_change = (char)(rand() % sizeof(char));
        }
    }
    return result;
}

int gpdgc_udp_randomly_send(int socket,
        void *message, size_t size, struct sockaddr *destination)
{
    size_t new_size = 0;
    void *new_msg = gpdgc_randomly_modify_message(message, size, &new_size);

    void *sent_msg = new_msg == NULL ? message : new_msg;
    size_t sent_size = new_msg == NULL ? size : new_size;
    if (sent_msg == NULL)
    {
        return 1;
    }

    char *label = gpdgc_get_address_label(destination);
    g_debug("%-10s: Send message (size=%lu) to '%s'", "UDP", sent_size, label);

    ssize_t bytes_sent = sendto(socket, sent_msg, sent_size, 0,
            destination, gpdgc_get_address_size(destination));
    free(new_msg);
    if (bytes_sent < 0)
    {
        g_warning("%-10s: Cannot send message to '%s': an error '%d' occured",
                "UDP", label, errno);
        return 0;
    }
    else if (sent_size != ((size_t)bytes_sent))
    {
        g_warning("%-10s: Cannot send message to '%s': "
                "%lu/ %lu bytes has been sent",
                "UDP", label, bytes_sent, sent_size);
        return 0;
    }
    free(label);
    return 1;
}

int gpdgc_udp_server_multicast(gpdgc_iserver *server, void *msg, size_t size)
{
    if (msg == NULL)
    {
        return 1;
    }

    int result = 1;
    GSList *iterator = server->servers;
    while (iterator != NULL)
    {
        gpdgc_process *dst = iterator->data;
        iterator = iterator->next;

        if ((gpdgc_cmp_process(dst, server->local) != 0) && (msg != NULL))
        {
            result &= gpdgc_udp_randomly_send(server->socket,
                    msg, size, dst->address);
        }
    }
    return result;
}

int gpdgc_udp_send(int socket,
        void *message, size_t size, struct sockaddr *destination)
{
    if (message == NULL)
    {
        return 1;
    }

    return gpdgc_udp_randomly_send(socket, message, size, destination);
}
