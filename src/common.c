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

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

#define GPDGC_COUNTER_THRESHOLD 1000000

/* Create structure to store information to be delivered to application */
gpdgc_output *gpdgc_create_output(unsigned short type, unsigned long id,
        void *content, size_t size, struct sockaddr *sender, gpdgc_event event)
{
    gpdgc_output *result = malloc(sizeof(gpdgc_output));
    if (result != NULL)
    {
        result->type = type; 
        result->event = event;

        result->id = id;
        result->content = content;
        result->size = size;
        result->sender = sender;
    }
    return result;
}

/* Free the memory occupied by information to be delivered to application */
void gpdgc_free_output(void *void_output)
{
    gpdgc_output *output= void_output;

    if (output->event == GPDGC_OUT_OF_MEMORY)
    {
        return;
    }
    free(output->content);
    free(output);
}


/* Print a S-Expression in a buffer */
void *gpdgc_get_gcry_sexp_t_as_buffer(gcry_sexp_t sexp, size_t *size)
{
    g_assert(sexp != NULL);

    size_t buf_size = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_CANON, NULL, 0);
    void *buf = malloc(buf_size);
    if (buf == NULL)
    {
        *size = 0;
        return NULL;
    }

    *size = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_CANON, buf, buf_size);
    if ((*size == 0) || (buf_size < *size))
    {
        g_error("Buffer S-Exp: invalid buffer size for S-Exp; "
                "expected=%ld used=%ld", buf_size, *size);
        *size = 0;
        free(buf);
        return NULL;
    }
    return buf;
}

/* Clone a S-Expression */
gcry_sexp_t gpdgc_clone_gcry_sexp_t(gcry_sexp_t sexp)
{
    if (sexp == NULL)
    {
        return NULL;
    }

    size_t size = 0;
    void *buffer = gpdgc_get_gcry_sexp_t_as_buffer(sexp, &size);
    if (buffer == NULL)
    {
        return NULL;
    }

    gcry_sexp_t clone;
    int failure = gcry_sexp_new(&clone, buffer, size, 0);
    free(buffer);
    return failure ? NULL : clone;
}

/* Compare two S-Expressions */
int gpdgc_cmp_gcry_sexp_t(gcry_sexp_t first, gcry_sexp_t second, GError **ex)
{
    g_assert((ex == NULL) || (*ex == NULL));

    if (first == NULL)
    {
        return second == NULL ? 0 : -1;
    }
    else if (second == NULL)
    {
        return 1;
    }

    size_t first_size = 0;
    void *first_buffer = gpdgc_get_gcry_sexp_t_as_buffer(first, &first_size);
    if (first_buffer == NULL)
    {
        g_set_error_literal(ex, G_FILE_ERROR, G_FILE_ERROR_NOMEM, "No memory");
        return 1;
    }

    size_t second_size = 0;
    void *second_buffer = gpdgc_get_gcry_sexp_t_as_buffer(second, &second_size);
    if (second_buffer == NULL)
    {
        free(first_buffer);
        g_set_error_literal(ex, G_FILE_ERROR, G_FILE_ERROR_NOMEM, "No memory");
        return 1;
    }

    if (first_size != second_size)
    {
        free(first_buffer);
        free(second_buffer);
        return first_size > second_size ? 1 : -1;
    }

    int result = memcmp(first_buffer, second_buffer, first_size);
    free(first_buffer);
    free(second_buffer);
    return result;
}


/* Compare two loop numbers */
int gpdgc_cmp_counter(unsigned long first, unsigned long second)
{
    /* NB: When reaching the limit, the next number is set to zero */ 
    unsigned long max = (unsigned long) -1;
    if (first == second)
    {
        return 0;
    }
    else if (((first < GPDGC_COUNTER_THRESHOLD)
                && (second > (max - GPDGC_COUNTER_THRESHOLD)))
            || ((first > second)
                && ((first <= (max - GPDGC_COUNTER_THRESHOLD))
                    || (second >= GPDGC_COUNTER_THRESHOLD))))
    {
        return 1;
    }    
    return -1;
}
int gpdgc_cmp_counter_pointer(unsigned long *first, unsigned long *second)
{
    return gpdgc_cmp_counter(*first, *second);
}


/* Compare two clocks */
int gpdgc_cmp_clock(unsigned long first_phase, unsigned long first_round,
        unsigned long first_step, unsigned long second_phase,
        unsigned long second_round, unsigned long second_step)
{
    int result = gpdgc_cmp_counter(first_phase, second_phase);
    if (result == 0)
    {
        result = gpdgc_cmp_counter(first_round, second_round);
        if ((result == 0) && (first_step != second_step))
        {
            result = first_step > second_step ? 1 : -1;
        }
    }
    return result;
}


/* Clone the specified socket address */
struct sockaddr *gpdgc_clone_address(struct sockaddr *address)
{
    size_t address_size = gpdgc_get_address_size(address);
    struct sockaddr *result = (struct sockaddr *) malloc(address_size);
    if (result != NULL)
    {
        memcpy(result, address, address_size);
    }
    return result;
}

/* Check if two group communication process addresses are equal */ 
int gpdgc_cmp_address(struct sockaddr *first, struct sockaddr *second)
{
    if ((first == NULL) && (second == NULL))
    {
        return 0;
    }
    if (first == NULL)
    {
        return -1;
    }
    if (second == NULL)
    {
        return 1;
    }

    if (first->sa_family != second->sa_family)
    {
        return (first->sa_family - second->sa_family);
    }

    size_t process_size = first->sa_family == AF_INET
        ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    return memcmp(first, second, process_size);
}

/* Check if the specified list of addresses contains the specified address */
int gpdgc_contains_address(GSList *addresses, struct sockaddr *address)
{
    GSList *iterator = addresses;
    while (iterator != NULL)
    {
        if (gpdgc_cmp_address(address, (struct sockaddr *) iterator->data) == 0)
        {
            return 1;
        }
        iterator = iterator->next;
    }
    return 0;
}

/* Return the address corresponding to the specified socket address */
char *gpdgc_get_address_label(struct sockaddr *address)
{
    g_assert(address != NULL);

    char *address_label = malloc(INET6_ADDRSTRLEN);
    short port = -1;
    if ((address_label != NULL) && (address->sa_family == AF_INET))
    {
        inet_ntop(address->sa_family,
                &((struct sockaddr_in *)address)->sin_addr,
                address_label, INET6_ADDRSTRLEN);
        port = ntohs(((struct sockaddr_in *)address)->sin_port);
    }
    else if ((address_label != NULL) && (address->sa_family == AF_INET6))
    {
        inet_ntop(address->sa_family,
                &((struct sockaddr_in6 *)address)->sin6_addr,
                address_label, INET6_ADDRSTRLEN);
        port = ntohs(((struct sockaddr_in6 *)address)->sin6_port);
    }

    char *result = NULL;
    if (port >= 0)
    {
        asprintf(&result, "%s:%d", address_label, port);
    }
    free(address_label);
    return result; 
}

/* Return the address size of the specified group communication process */
size_t gpdgc_get_address_size(struct sockaddr *address)
{
    return address->sa_family == AF_INET 
        ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
}

/* Return the address size of the specified group communication process */
size_t gpdgc_get_max_address_size()
{
    return sizeof(struct sockaddr_in) > sizeof(struct sockaddr_in6)
        ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
}

/* Check that the buffer corresponds to an address */
int gpdgc_is_address(void *buffer, size_t size)
{
    struct sockaddr *addr = buffer;
    if (size == sizeof(struct sockaddr_in))
    {
        return addr->sa_family == AF_INET;
    }
    else if (size == sizeof(struct sockaddr_in6))
    {
        return addr->sa_family == AF_INET6;
    }
    return 0;
}


/* Send the specified message to the specified address */
int gpdgc_udp_send(int socket,
        void *message, size_t size, struct sockaddr *destination)
{
    if (message == NULL)
    {
        return 1;
    }

    char *label = gpdgc_get_address_label(destination);
    g_debug("%-10s: Send message (size=%lu) to '%s'", "UDP", size, label);

    ssize_t bytes_sent = sendto(socket, message, size, 0,
            destination, gpdgc_get_address_size(destination));
    if (bytes_sent < 0)
    {
        g_warning("%-10s: Cannot send message to '%s': an error '%d' occured",
                "UDP", label, errno);
        return 0;
    }
    else if (size != ((size_t)bytes_sent))
    {
        g_warning("%-10s: Cannot send message to '%s': "
                "%lu/ %lu bytes has been sent", "UDP", label, bytes_sent, size);
        return 0;
    }
    free(label);
    return 1;
}

/* Multicast the specified message to the specified addresses */
int gpdgc_udp_multicast(int socket, 
        void *message, size_t size, GSList *destinations)
{
    int result = 1;
    GSList *iterator = destinations;
    while (iterator != NULL)
    {
        struct sockaddr *destination = iterator->data;
        iterator = iterator->next;

        result = result && gpdgc_udp_send(socket, message, size, destination);
    }
    return result;
}
