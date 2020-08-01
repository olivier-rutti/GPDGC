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
#ifndef GPDGC_HEARDOF_H_INCLUDED
#define GPDGC_HEARDOF_H_INCLUDED

#include <glib.h>
#include <pthread.h>

#include "common.h"
#include "server.h"

/******************************************************************************
 * heardof.h implements the round mecanism on which the consensus protocol rely
 *****************************************************************************/

#define GPDGC_FIXED_STEP                        99
#define GPDGC_REASONNABLE_FUTUR_PHASE_THRESHOLD  5
#define GPDGC_REASONNABLE_FUTUR_ROUND_THRESHOLD 50

#define GPDGC_ROUND_CONSISTENT_FLAG              1
#define GPDGC_ROUND_COORDINATOR_ONLY_FLAG        2
#define GPDGC_ROUND_PENDING_FLAG                 4

#define GPDGC_ROUND_MESSAGE_SAFE_FLAG            1
#define GPDGC_ROUND_MESSAGE_RECEIVED_FLAG        2

/* Check if the current heard-of step can be terminated */
void gpdgc_check_end_of_heardof_step(gpdgc_iserver *server, int late_sync);

/* Start a Heard-Of round (identified with the phase and the round number)
 * NB: (1) The predicate P(CONS) is eventually guaranteed when
 *         'require_consistency' is set to true. 
 *     (2) Participants of the round may sends an empty message.
 *     (3) The parameter 'coordinator' is required for the implementation of
 *         P(CONS) and could be ignored when 'require_consistency' is false */
int gpdgc_start_heardof_round(gpdgc_iserver *server, unsigned long phase, 
        unsigned long round, unsigned short flags, gpdgc_message *message);

/* Deliver a transpot message to Heard-Of */
void gpdgc_deliver_to_heardof(gpdgc_iserver *server,
        gpdgc_message *message, gpdgc_process *sender);
#endif
