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

void *gpdgc_maliciously_modify_message(void *buffer, gcry_sexp_t key,
        size_t buffer_size, size_t *size)
{
    *size = 0;
    gpdgc_message *message = gpdgc_extract_contents(buffer, buffer_size);
    size_t first_size = gpdgc_get_content_size(message, 0);
    if (first_size != sizeof(unsigned short))
    {
        gpdgc_pop_content(message, NULL);
        first_size = gpdgc_get_content_size(message, 0);
    }
    if (first_size != sizeof(unsigned short))
    {
        gpdgc_free_message(message);
        return NULL;
    }
    
    int message_length = g_slist_length(message->contents);
    int content_to_change_index = rand() % message_length;
    GSList *nth_item = g_slist_nth(message->contents, content_to_change_index);
    gpdgc_content *content_to_change = (gpdgc_content *) nth_item->data;

    int nb_proposal = content_to_change->size / sizeof(unsigned long);
    if (content_to_change->size == sizeof(unsigned short))
    {
        unsigned short *content = (unsigned short *) content_to_change->content;
        *content = *content - 32 + (rand() % 65);
    }
    else if (content_to_change->size == sizeof(unsigned long))
    {
        unsigned long *content = (unsigned long *) content_to_change->content;
        *content = *content - 32 + (rand() % 65);
    }
    else if (content_to_change->size == nb_proposal * sizeof(unsigned long))
    {
        unsigned long *values = (unsigned long *) content_to_change->content;
        for (int i = 0; i< nb_proposal; i++)
        {
            values[i] = values[i] - 5 + (rand() % 11);
        }
    }
    else 
    {
       int index_to_change = rand() % content_to_change->size;
       char *byte_to_change =
           ((char *)content_to_change->content) + index_to_change;
       *byte_to_change = (char)(rand() % sizeof(char));
    }
    void *result = gpdgc_write_contents(message, key, size);
    gpdgc_free_message(message);
    return result;
}

int gpdgc_udp_maliciously_send(int socket, gcry_sexp_t key,
        void *message, size_t size, struct sockaddr *destination)
{
    size_t new_size = 0;
    void *new_msg =
        gpdgc_maliciously_modify_message(message, key, size, &new_size);

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
    gcry_sexp_t key = gpdgc_get_channel_key(server);
    
    int result = 1;
    GSList *iterator = server->servers;
    while (iterator != NULL)
    {
        gpdgc_process *dst = iterator->data;
        iterator = iterator->next;

        if ((gpdgc_cmp_process(dst, server->local) != 0) && (msg != NULL))
        {
            result &= gpdgc_udp_maliciously_send(server->socket, key,
                    msg, size, dst->address);
        }
    }
    return result;
}

int gpdgc_udp_send(int socket,
        void *message, size_t size, struct sockaddr *destination)
{
    return gpdgc_udp_maliciously_send(socket, NULL, message, size, destination);
}
