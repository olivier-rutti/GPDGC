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
#ifndef GPDGC_CONSENSUS_H_INCLUDED
#define GPDGC_CONSENSUS_H_INCLUDED

#include <glib.h>

#include "common.h"
#include "server.h"

/******************************************************************************
 * consensus.h implements the consensus protocol which basically allows a set
 *  of processes to agree on a common value
 *****************************************************************************/

/* Timestamped vote */ 
typedef struct
{
    void *vote;
    size_t size;

    unsigned long timestamp;
} gpdgc_timed_vote;

/* Free the memory occupied by a timed vote */ 
void gpdgc_free_timed_vote(void *vote);
/* Get the max length of consensus message */
size_t gpdgc_get_proposition_length(gpdgc_validation_type validation);
/* Get the size of a proposition */
size_t gpdgc_get_proposition_size(unsigned int nb_servers,
        unsigned int nb_clients, gpdgc_validation_type validation);
/* Get a consensus vote as a string */ 
char *gpdgc_get_vote_label(void *proposal, size_t size);


/* Start a consensus instance */
int gpdgc_start_consensus(gpdgc_iserver *server,
        unsigned long phase, unsigned long *values);

/* Signal that a set of heard-of messages is ready for consensus */
void gpdgc_deliver_heardof_round(gpdgc_iserver *server, 
        unsigned long phase, unsigned long round);

/* Get the specified phase decision */
gpdgc_message *gpdgc_get_decision(gpdgc_iserver *server, unsigned long phase);
#endif
