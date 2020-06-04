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
#ifndef GPDGC_COMMON_H_INCLUDED
#define GPDGC_COMMON_H_INCLUDED

#include <gcrypt.h>
#include <glib.h>
#include <sys/socket.h>

#include "gpdgc.h"

/******************************************************************************
 * common.h exposes basic types and methods common to both clients and servers
 *****************************************************************************/

#define UNUSED(x) (void)(x)

#define GPDGC_CRASHED_FLAG               1
#define GPDGC_BYZANTINE_FLAG             2

#define GPDGC_MAX_PROCESS_LABEL_SIZE   100
#define GPDGC_MAX_KEY_SIZE            8192

/* The list of states of GPDGC server/client */
typedef enum 
{
    GPDGC_CREATED = 0, 
    GPDGC_WAITING = 1,
    GPDGC_READY   = 2,
    GPDGC_EXITING = 3,
    GPDGC_DONE    = 4, 
    GPDGC_CLOSED  = 5 
} gpdgc_state;

/* Informations deliverable to applications through callbacks */
typedef struct
{
    unsigned short type;
    gpdgc_event event;

    unsigned long id;
    void *content;
    size_t size;
    struct sockaddr *sender;
} gpdgc_output;

/* Create structure to store information to be delivered to application */
gpdgc_output *gpdgc_create_output(unsigned short type, unsigned long id,
        void *content, size_t size, struct sockaddr *sender, gpdgc_event event);
/* Free the memory occupied by information to be delivered to application */
void gpdgc_free_output(void *output);

/* Print a S-Expression in a buffer */
void *gpdgc_get_gcry_sexp_t_as_buffer(gcry_sexp_t sexp, size_t *size);
/* Clone a S-Expression */
gcry_sexp_t gpdgc_clone_gcry_sexp_t(gcry_sexp_t sexp);
/* Compare two S-Expressions */
int gpdgc_cmp_gcry_sexp_t(gcry_sexp_t first, gcry_sexp_t second, GError **ex);

/* Compare counters with the following two assumptions:
 *  (1) a counter restarts from zero when its reaches its value limit
 *  (2) a counter with a value close to the limit is smaller than a counter
 *        close to zero
 * Contrary to classic comparison, this method is therefore not transitiv. */
int gpdgc_cmp_counter(unsigned long first, unsigned long second);
int gpdgc_cmp_counter_pointer(unsigned long *first, unsigned long *second);

/* Compare clocks composed of a phase, a round and a step in which the above
 *  two assumptions apply on both the phase and the round 
 * NB: Considering such property for clocks is necessary to allow processes to 
 *  be executed during a very very long period */
int gpdgc_cmp_clock(unsigned long first_phase, unsigned long first_round,
        unsigned long first_step, unsigned long second_phase,
        unsigned long second_round, unsigned long second_step);

/* Clone the specified socket adress */
struct sockaddr *gpdgc_clone_address(struct sockaddr *address);
/* Compare two process adresses */
int gpdgc_cmp_address(struct sockaddr *first, struct sockaddr *second);
/* Check whether a list of adresses contains the specified process address */
int gpdgc_contains_address(GSList *addresses, struct sockaddr *address);
/* Get the string corresponding to the specified process address */
char *gpdgc_get_address_label(struct sockaddr *address);
/* Return the size in memory used by the specified process adress */
size_t gpdgc_get_address_size(struct sockaddr *address);
/* Return the maximal size in memory of a process adress */
size_t gpdgc_get_max_address_size();
/* Check that the buffer corresponds to an address */
int gpdgc_is_address(void *buffer, size_t size);

/* Send the specified message to the specified address */
int gpdgc_udp_send(int socket,
        void *message, size_t size, struct sockaddr *destination);
/* Multicast the specified message to the specified addresses */
int gpdgc_udp_multicast(int socket, 
        void *message, size_t size, GSList *destinations);
#endif 
