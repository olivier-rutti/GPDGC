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
#include <stdlib.h>
#include <string.h>

#include "heardof.h"
#include "consensus.h"
#include "process.h"

/* Add a message to the list messages to be processed in the future */
int gpdgc_cmp_future(const void *first_void, const void *second_void)
{
    const gpdgc_future *first = first_void;
    const gpdgc_future *second = second_void;

    int result = gpdgc_cmp_counter(first->phase, second->phase);
    if (result == 0)
    {
        result = gpdgc_cmp_counter(first->round, second->round);
        if (result == 0)
        {
            if (first->step == GPDGC_FIXED_STEP)
            {
                return (first->step != second->step) ? -1 : 0;
            }
            else if (second->step == GPDGC_FIXED_STEP)
            {
                return (first->step != second->step) ? 1 : 0;
            }
            return gpdgc_cmp_counter(first->step, second->step);
        }
    }
    return result;


    return gpdgc_cmp_clock(first->phase, first->round, first->step, 
                           second->phase, second->round, second->step);
}
void gpdgc_cache_message(gpdgc_iserver *server, unsigned long phase,
        unsigned long round, unsigned long step, gpdgc_message *message,
        gpdgc_process *process)
{
    unsigned short counter = 0;
    GSList *iterator = process->futures;
    while (iterator != NULL)
    {
        gpdgc_future *future = iterator->data;
        iterator = iterator->next;

        int cmp_clock = gpdgc_cmp_clock(future->phase, future->round, 
                future->step, phase, round, step);
        if (cmp_clock == 0)
        {
            g_info("%-10s: A message '%s:%lu:%lu:%lu' has been already cached",
                    "HEARD_OF", process->label, phase, round, step);
            gpdgc_free_message(message);
            return;
        }
        else if (counter < server->max_futures - (cmp_clock < 0 ? 0 : 1))
        {
            counter++;
        }
        else
        {
            process->futures = g_slist_remove(process->futures, future);
            gpdgc_free_future(future);
        }
    }

    /* If the checks are successful, effectively cache the message */
    if (counter < server->max_futures)
    {
        gpdgc_future *future = malloc(sizeof(gpdgc_future)); 
        if (future == NULL)
        {
            gpdgc_signal_lack_of_memory(server,
                    "%-10s: Cannot cache future message '%s:%lu:%lu:%lu'",
                    "HEARD_OF", process->label, phase, round, step);
            return;
        }
        future->phase = phase;
        future->round = round;
        future->step = step;
        future->message = message;

        g_debug("%-10s: Cache future message '%s:%lu:%lu:%lu'",
                "HEARD_OF", process->label, phase, round, step);
        process->futures = g_slist_insert_sorted(process->futures, 
                future, gpdgc_cmp_future);
    }
    else
    {
        g_info("%-10s: Ignore message '%s:%lu:%lu:%lu': cache is full",
                "HEARD_OF", process->label, phase, round, step);
        gpdgc_free_message(message);
    }
}


/* Process received messages from the first step */
int gpdgc_check_message_signature(gpdgc_message *msg, gcry_sexp_t public_key,
        unsigned long phase, unsigned long round, unsigned long step) 
{
    if (gpdgc_unsign_message(msg, public_key))
    {
        size_t msg_phase_size;
        unsigned long *msg_phase = gpdgc_pop_content(msg, &msg_phase_size);

        size_t msg_round_size;
        unsigned long *msg_round = gpdgc_pop_content(msg, &msg_round_size);

        size_t msg_step_size;
        unsigned long *msg_step = gpdgc_pop_content(msg, &msg_step_size);

        int result = (msg_phase_size == sizeof(unsigned long))
            && (msg_round_size == sizeof(unsigned long))
            && (msg_step_size == sizeof(unsigned long))
            && (*msg_phase == phase)
            && (((*msg_round == round) && (*msg_step == step))
                    || ((*msg_round == 0) && (*msg_step == GPDGC_FIXED_STEP)));

        free(msg_phase);
        free(msg_round);
        free(msg_step);
        return result;
    }
    return 0;
}
void gpdgc_process_message_single(gpdgc_iserver *server,
        gpdgc_message *msg, gpdgc_process *sender)
{
    gpdgc_process *coordinator = server->coordinator->data; 
    gpdgc_process *local = server->local;

    /* Check the message signature if required */ 
    if ((server->round_flags & GPDGC_ROUND_CONSISTENT_FLAG)
            && (local->step == 0)
            && gpdgc_has_certified_servers(server)
            && (gpdgc_cmp_process(local, coordinator) != 0)
            && (!gpdgc_check_message_signature(msg, sender->public_key, 
                    local->phase, local->round, local->step)))
    {
        g_info("%-10s: Message '%s:%lu:%lu:%lu' has not a correct signature",
                "HEARD_OF", sender->label, local->phase, local->round,
                local->step);
        gpdgc_free_message(msg);
        return;
    }

    /* Store the message */
    g_debug("%-10s: Store message '%s:%lu:%lu:%lu'",
            "HEARD_OF", sender->label, local->phase, local->round, local->step);
    sender->current->message = msg;
    sender->current->counter = 1;
}

/* Process received decision messages */
void gpdgc_process_message_decision(gpdgc_iserver *server,
        gpdgc_message *msg, gpdgc_process *sender)
{
    /* Store the message if not already received */
    if (sender->current->decision == NULL)
    {
        g_debug("%-10s: Store decision message '%s:%lu:0:%d'",
                "HEARD_OF", sender->label, server->local->phase,
                GPDGC_FIXED_STEP);
        sender->current->decision = msg;
    }
    else
    {
        g_info("%-10s: Ignore already received decision message '%s:%lu:0:%d'",
                "HEARD_OF", sender->label, server->local->phase,
                GPDGC_FIXED_STEP);
        gpdgc_free_message(msg);
    }
}

/* Process received messages from second step and after */
unsigned int gpdgc_get_round_threshold(gpdgc_iserver *server)
{
    if ((server->round_flags & GPDGC_ROUND_CONSISTENT_FLAG) 
        && gpdgc_is_byzantine_model(server)
        && (!gpdgc_has_certified_servers(server))
        && (server->local->step > 0))
    {
        unsigned short multiplier = (server->local->step == 1) ? 2 : 1;
        
        return multiplier * gpdgc_get_max_byzantine(server);
    }
    return 0;
}
void gpdgc_process_message_set(gpdgc_iserver *server, 
        gpdgc_message *message, gpdgc_process *sender)
{
    int is_byzantine = gpdgc_is_byzantine_model(server);
    int is_certified = gpdgc_has_certified_servers(server);

    gpdgc_process *coordinator = server->coordinator->data; 
    int is_sender_coord = gpdgc_cmp_process(coordinator, sender) == 0;

    gpdgc_process *local = server->local;
    int byzantine_with_signature_sub_message =
        is_byzantine && is_certified && is_sender_coord && (local->step == 1);
    int byzantine_sub_message =
        is_byzantine && (!is_certified) && (local->step == 1);
    int byzantine_sub_message_from_coord = is_byzantine && (!is_certified)
        && is_sender_coord && (local->step == 2);
    if ((!byzantine_with_signature_sub_message)
            && (!byzantine_sub_message)
            && (!byzantine_sub_message_from_coord))
    {
        g_warning("%-10s: Message set '%lu:%lu:%lu' [%s]: cannot be processed",
                "HEARD_OF", local->phase, local->round, local->step,
                is_sender_coord ? "C" : "NC");
        gpdgc_free_message(message);
        return;
    }

    while (message->contents != NULL)
    {
        /* Extract a sub message from the message */
        size_t size;
        void *buffer = gpdgc_pop_content(message, &size);

        gpdgc_message *sub_message = gpdgc_extract_contents(buffer, size);
        gpdgc_process *sub_sender = NULL;
        if (sub_message != NULL)
        {
            struct sockaddr *tmp_sender = gpdgc_pop_address(sub_message);
            if (tmp_sender != NULL)
            {
                sub_sender = gpdgc_get_server(server, tmp_sender);
                free(tmp_sender);
            }
        }
        free(buffer);

        /* Process the sub message */
        if ((sub_message == NULL) || (sub_sender == NULL))
        {
            g_info("%-10s: Sub message '%lu:%lu:%lu': "
                    "empty message or invalid sender",
                    "HEARD_OF", local->phase, local->round, local->step);
            gpdgc_free_message(sub_message);
        }
        else if (byzantine_with_signature_sub_message) 
        {
            if (!gpdgc_check_message_signature(sub_message,
                        sub_sender->public_key, local->phase, local->round, 0))
            {
                g_info("%-10s: Message '%s:%lu:%lu:%lu' has invalid signature",
                        "HEARD_OF", sub_sender->label,
                        local->phase, local->round, local->step);
                gpdgc_free_message(sub_message);
            }
            else
            {
                gpdgc_free_message(sub_sender->current->message);
                sub_sender->current->message = sub_message;
                sub_sender->current->counter = 1;
                g_debug("%-10s: Store coherent sub message '%s:%lu:%lu:%lu'",
                        "HEARD_OF", sub_sender->label, 
                        local->phase, local->round, local->step);
            }	    
        }
        else if (byzantine_sub_message)
        {
            sub_sender->current->votes = is_sender_coord
                ? sub_sender->current->votes
                : g_slist_append(sub_sender->current->votes, sub_message);
            if ((sub_sender->current->message != NULL)
                    && (gpdgc_cmp_message(sub_message, 
                            sub_sender->current->message) == 0))
            {
                sub_sender->current->counter = sub_sender->current->counter + 1;
            }
            g_debug("%-10s: Store sub message '%s:%lu:%lu:%lu': counter=%d",
                    "HEARD_OF", sub_sender->label, local->phase, local->round,
                    local->step, sub_sender->current->counter);
            if (is_sender_coord)
            {
                gpdgc_free_message(sub_message);
            }
        }
        else if (byzantine_sub_message_from_coord)
        {
            unsigned int counter = 1;
            GSList *iterator = sub_sender->current->votes;
            while (iterator != NULL)
            {
                gpdgc_message *vote = iterator->data;
                iterator = iterator->next;

                if (gpdgc_cmp_message(sub_message, vote) == 0)
                {
                    counter++;
                }
            }

            int store = counter > gpdgc_get_max_byzantine(server);
            g_debug("%-10s: %s coherent sub message '%s:%lu:%lu:%lu'",
                    "HEARD_OF", store ? "Store" : "Ignore",
                    sub_sender->label, local->phase, local->round, local->step);
            if (store)
            {
                gpdgc_free_message(sub_sender->current->message);
                sub_sender->current->message = sub_message;
                sub_sender->current->counter = counter;
            }
            else
            {
                gpdgc_free_message(sub_message);
            }
        }
    }
    gpdgc_free_message(message);
}

/* Process message */
void gpdgc_process_message(gpdgc_iserver *server,
        gpdgc_message *msg, unsigned long step, gpdgc_process *sender)
{
    if (step == GPDGC_FIXED_STEP)
    {
        gpdgc_process_message_decision(server, msg, sender);
        return;
    }

    /* Avoid that a process deliver twice a message in a specific step */ 
    if (sender->current->flags & GPDGC_ROUND_MESSAGE_RECEIVED_FLAG) 
    {
        g_info("%-10s: Message '%s:%lu:%lu:%lu' has already been received",
                "HEARD_OF", sender->label, server->local->phase,
                server->local->round, server->local->step);
        gpdgc_free_message(msg);
        return;
    }
    sender->current->flags |= GPDGC_ROUND_MESSAGE_RECEIVED_FLAG;

    /* Effectively process the message */
    if (step == 0)
    {
        gpdgc_process_message_single(server, msg, sender);
    }
    else
    {
        gpdgc_process_message_set(server, msg, sender);
    }
}


/* Check if the current heard-of step can be terminated */
int gpdgc_start_heardof_step(gpdgc_iserver *server, gpdgc_message *message);
unsigned long gpdgc_get_round_ticks(unsigned long round, 
        unsigned long initial, unsigned long increment)
{
    if ((((unsigned long) -1) - initial) / increment > round)
    {
        return initial + round * increment;
    }
    return (unsigned long) -1;
}
int gpdgc_recv_from_coord_only(gpdgc_iserver *server)
{
    unsigned long step = gpdgc_has_certified_servers(server) ? 1 : 2;

    return gpdgc_is_byzantine_model(server) && (server->local->step == step); 
}
int gpdgc_is_final_step(gpdgc_iserver *server)
{
    unsigned long final_step = 0;
    if ((server->round_flags & GPDGC_ROUND_CONSISTENT_FLAG)
        && gpdgc_is_byzantine_model(server))
    {
        final_step = gpdgc_has_certified_servers(server) ? 1 : 2;
    }
    return server->local->step >= final_step;
}
int gpdgc_received_all_step_messages(gpdgc_iserver *server)
{
    if ((server->round_flags & GPDGC_ROUND_COORDINATOR_ONLY_FLAG)
        || gpdgc_recv_from_coord_only(server))
    {
        gpdgc_process *coord = server->coordinator->data;

        return coord->current->flags & GPDGC_ROUND_MESSAGE_RECEIVED_FLAG;
    }

    int result = 1;
    unsigned int nb_decisions = gpdgc_get_max_byzantine(server) + 1;
    GSList *sender_iterator = server->servers;
    while ((nb_decisions > 0) && (sender_iterator != NULL))
    {
        gpdgc_process *sender = sender_iterator->data;
        sender_iterator = sender_iterator->next;

        if (sender->current->decision != NULL)
        {
            nb_decisions--;
        }
        result = result
            && sender->current->flags & GPDGC_ROUND_MESSAGE_RECEIVED_FLAG;
    }
    return result || (nb_decisions == 0);
}
void *gpdgc_write_round(gpdgc_process *server,
        unsigned int threshold, int allow_decision, size_t *size)
{
    gpdgc_message *message = NULL;
    *size = 0;
    gpdgc_round *current = server->current;
    if ((current->message != NULL) && (current->counter > threshold))
    {
        message = current->message;
    }
    else if ((current->decision != NULL) && allow_decision)
    {
        message = current->decision;
    }

    void *result = NULL;
    if (message != NULL)
    {
        size_t addr_size = gpdgc_get_address_size(server->address);
        if (gpdgc_push_content(current->message, server->address, addr_size))
        {
            result = gpdgc_write_contents(current->message, NULL, size);
            gpdgc_pop_content(current->message, NULL);
        }
    }
    return result;
}
void gpdgc_check_end_of_heardof_step(gpdgc_iserver *server)
{
    if (!(server->round_flags & GPDGC_ROUND_PENDING_FLAG))
    {
        return;
    }

    gpdgc_process *local = server->local;
    gpdgc_process *sync = gpdgc_get_synchronized_server(server);
    gpdgc_process *coord = server->coordinator->data;
    int cmp_sync_clock = gpdgc_cmp_clock(sync->phase, sync->round, sync->step,
            local->phase, local->round, local->step);
    unsigned int threshold = gpdgc_get_round_threshold(server);
    unsigned long round_ticks = gpdgc_get_round_ticks(local->round,
            server->round_period_initial, server->round_period_increment);
    unsigned long elapsed_ticks = round_ticks - server->step_remaining_ticks;

    if (gpdgc_received_all_step_messages(server)
            || ((cmp_sync_clock > 0)
                && (elapsed_ticks >= server->round_period_initial))
            || ((cmp_sync_clock == 0) && (server->step_remaining_ticks == 0)))
    {
        g_debug("%-10s: Current step '%lu:%lu:%lu' is finished",
                "HEARD_OF", local->phase, local->round, local->step);

        if (gpdgc_is_final_step(server))
        {
            /* Check which messages are correct w.r.t. round flags */
            unsigned int nb_safes = 0;
            unsigned int nb_others = 0;
            GSList *iterator = server->servers;
            while (iterator != NULL)
            {
                gpdgc_process *iterated = iterator->data;
                iterator = iterator->next;

                if (iterated->current->counter > threshold)
                {
                    iterated->current->flags |= GPDGC_ROUND_MESSAGE_SAFE_FLAG;
                    nb_safes++;
                }
                else if (iterated->current->message != NULL)
                {
                    nb_others++;
                }
                g_slist_free_full(iterated->current->votes, gpdgc_free_message);
                iterated->current->votes = NULL;
                iterated->current->counter = 0;
            }

            /* Close the round by delivering the set of messages */
            unsigned long round = local->round;
            local->round = local->round + 1;

            free(server->clock_cache);
            server->clock_cache = NULL;
            server->clock_cache_size = 0;
            server->round_flags = 0;

            g_debug("%-10s: Deliver %u (+%u) messages for round '%lu:%lu'",
                    "HEARD_OF", nb_safes, nb_others, local->phase, round);
            gpdgc_deliver_heardof_round(server, local->phase, round);
        }
        else
        {
            /* Create a message for the next step: 
             * this message contains all messages received in the first step */
            local->step = local->step + 1;
            gpdgc_message *received = NULL;
            unsigned int received_count = 0;
            if ((gpdgc_cmp_process(coord, local) == 0)
                || (!gpdgc_recv_from_coord_only(server)))
            {
                received = gpdgc_create_message();
                if (received == NULL) 
                {
                    gpdgc_signal_lack_of_memory(server,
                            "%-10s: The message set for round '%lu:%lu:%lu' "
                            "cannot be build", "HEARD_OF",
                            local->phase, local->round, local->step);
                    gpdgc_free_message(received);
                    received = NULL;
                }

                GSList *iterator = server->servers;
                while ((iterator != NULL) && (received != NULL))
                {
                    gpdgc_process *iterated = iterator->data;
                    iterator = iterator->next;

                    size_t size;
                    void *buffer = gpdgc_write_round(iterated,
                            threshold, local->step == 1, &size);
                    int push = gpdgc_push_content(received, buffer, size);
                    received_count += buffer != NULL ? 1 : 0;
                    free(buffer);

                    if (!push)
                    {
                        gpdgc_signal_lack_of_memory(server,
                                "%-10s: The message set for round "
                                "'%lu:%lu:%lu' cannot be build", "HEARD_OF",
                                local->phase, local->round, local->step);
                        gpdgc_free_message(received);
                        received = NULL;
                        received_count = 0;
                    }
                }
            }

            g_debug("%-10s: The message set (size=%d) for round '%lu:%lu:%lu' "
                    "is build", "HEARD_OF", received_count,
                    local->phase, local->round, local->step);
            gpdgc_start_heardof_step(server, received);
        }
    }
}


/* Start a Heard-Of round (identified with the phase and the round number)
 * NB: (1) The predicate P(CONS) is eventually guaranteed when consistency
 *         flag is set to true.
 *         'ho_consistency' is set to true. 
 *     (2) Participants of the round may sends an empty message.
 *     (3) The parameter 'coordinator' is required for the implementation of
 *         P(CONS) and could be ignored when consistency flag is not set */
int gpdgc_build_heardof_message(gpdgc_iserver *server, gpdgc_message *message,
        unsigned long phase, unsigned long round, unsigned long step)
{
    unsigned short type = GPDGC_HEARDOF_MESSAGE_TYPE;
    
    /* Push a signed clock */
    if ((server->round_flags & GPDGC_ROUND_CONSISTENT_FLAG)
            && (step == 0) && gpdgc_has_certified_servers(server))
    {
        if ((!gpdgc_push_content(message, &step, sizeof(unsigned long)))
                || (!gpdgc_push_content(message, &round, sizeof(unsigned long)))
                || (!gpdgc_push_content(message, &phase, sizeof(unsigned long)))
                || (!gpdgc_sign_message(message, server->private_key)))
        {	     
            gpdgc_signal_lack_of_memory(server,
                    "%-10s: Message '%lu:%lu:%lu' cannot be signed",
                    "HEARD_OF", phase, round, step);
            return 0;
        }	  
        g_debug("%-10s: Sign the message '%lu:%lu:%lu'",
                "HEARD_OF", phase, round, step);
    }

    /* Push clock and message type */
    if ((!gpdgc_push_content(message, &step, sizeof(unsigned long)))
            || (!gpdgc_push_content(message, &round, sizeof(unsigned long)))
            || (!gpdgc_push_content(message, &phase, sizeof(unsigned long))) 
            || (!gpdgc_push_content(message, &type, sizeof(unsigned short))))
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Message '%lu:%lu:%lu' cannot be clocked",
                "HEARD_OF", phase, round, step);
        return 0;
    }
    return 1;
}
int gpdgc_start_heardof_step(gpdgc_iserver *server, gpdgc_message *message)
{
    gpdgc_process *local = server->local;

    /* Init the tick counter and the flags */
    GSList *iterator = server->servers;
    while (iterator != NULL)
    {
        gpdgc_process *iterated = iterator->data;
        iterator = iterator->next;

        iterated->current->flags = 0;
    }
    server->step_remaining_ticks = gpdgc_get_round_ticks(local->round,
            server->round_period_initial, server->round_period_increment);
    g_debug("%-10s: The step '%lu:%lu:%lu' is started",
            "HEARD_OF", local->phase, local->round, local->step); 

    /* Init the clock cache */
    int is_byzantine = gpdgc_is_byzantine_model(server);
    if (is_byzantine)
    {
        free(server->clock_cache);
        server->clock_cache_size = 0;

        gpdgc_message *clock = gpdgc_create_message();
        size_t clock_item_size = sizeof(unsigned long);
        unsigned short type = GPDGC_HEARDOF_MESSAGE_TYPE;
        if ((clock == NULL)
                || (!gpdgc_push_content(clock, &local->step, clock_item_size))
                || (!gpdgc_push_content(clock, &local->round, clock_item_size))
                || (!gpdgc_push_content(clock, &local->phase, clock_item_size))
                || (!gpdgc_push_content(clock, &type, sizeof(unsigned short))))
        {
            gpdgc_signal_lack_of_memory(server,
                    "%-10s: Clock '%lu:%lu:%lu' cannot be built",
                    "HEARD_OF", local->phase, local->round, local->step);
            server->clock_cache = NULL;
        }
        else
        {
            gcry_sexp_t key = gpdgc_get_channel_key(server);
            server->clock_cache =
                gpdgc_write_contents(clock, key, &server->clock_cache_size);
            if (server->clock_cache == NULL)
            {
                gpdgc_signal_lack_of_memory(server,
                        "%-10s: Clock '%lu:%lu:%lu' cannot be buffered",
                        "HEARD_OF", local->phase, local->round, local->step);
            }
            else
            {
                server->clock_remaining_ticks = server->resend_period;
            }
        }
        gpdgc_free_message(clock);
    }

    /* Compute the role of the local process */
    gpdgc_process *coord = server->coordinator->data;
    int is_coord = gpdgc_cmp_process(coord, local) == 0;
    int belongs_to_senders =
        server->round_flags & GPDGC_ROUND_COORDINATOR_ONLY_FLAG 
        ? is_coord : gpdgc_get_server(server, local->address) != NULL;
    int is_message_sender = ((local->step == 0) && belongs_to_senders)
        || ((local->step > 0)
                && (is_coord || (!gpdgc_recv_from_coord_only(server))));

    /* Reset messages when consistency must be ensured */ 
    if ((server->round_flags & GPDGC_ROUND_CONSISTENT_FLAG)
            && (local->step > 0))
    {
        GSList *iterator = server->servers;
        while(iterator != NULL)
        {
            gpdgc_process *iterated = iterator->data;
            iterator = iterator->next;

            iterated->current->counter = 0;
        }
        g_debug("%-10s: Init the counter for all received messages", 
                "HEARD_OF");  
    }

    /* Retrieve the message already received for this round,
     *  and clean cache messages that are deprecated */
    GSList *server_iterator = server->servers;
    while (server_iterator != NULL)
    {
        gpdgc_process *iterated = server_iterator->data;
        server_iterator = server_iterator->next;

        GSList *message_iterator = iterated->futures;
        while (message_iterator != NULL)
        {
            gpdgc_future *future = message_iterator->data;

            int cmp_result = gpdgc_cmp_clock(local->phase, local->round,
                    local->step, future->phase, future->round, future->step);
            message_iterator = cmp_result >= 0 ? message_iterator->next : NULL;
            if (cmp_result >= 0)
            {
                iterated->futures = g_slist_remove(iterated->futures, future);
                if ((cmp_result == 0) ||
                        ((local->phase == future->phase)
                         && (local->round == future->round)
                         && (future->step == GPDGC_FIXED_STEP)))
                {
                    g_debug("%-10s: Process cached message '%s:%lu:%lu:%lu'",
                            "HEARD_OF", iterated->label, future->phase, 
                            future->round, future->step);
                    gpdgc_process_message(server,
                            future->message, future->step, iterated);
                    future->message = NULL;
                }
                gpdgc_free_future(future);
            }
        }
    }

    /* Broadcast it to all servers if local is a sender */ 
    int result = 1;
    if (is_message_sender && (message!= NULL))
    {
        /* Build the message to be sent */
        if (!gpdgc_build_heardof_message(server, message,
                    local->phase, local->round, local->step))
        {
            gpdgc_free_message(message);
            return 0;
        }

        /* Buffer the message */
        gcry_sexp_t key = gpdgc_get_channel_key(server);
        size_t size = 0;
        void *buffer = gpdgc_write_contents(message, key, &size);
        if (buffer == NULL)
        {
            gpdgc_signal_lack_of_memory(server,
                    "%-10s: Message '%lu:%lu:%lu' cannot be buffered",
                    "HEARD_OF", local->phase, local->round, local->step);
            gpdgc_free_message(message);
            return 0;
        }

        /* Send the message */
        g_debug("%-10s: Multicast message '%lu:%lu:%lu'",
                "HEARD_OF", local->phase, local->round, local->step);
        result = gpdgc_udp_server_multicast(server, buffer, size); 
        free(buffer);

        gpdgc_pop_content(message, NULL);
        gpdgc_deliver_to_heardof(server, message, local);
    }
    return result;  
}
int gpdgc_start_heardof_round(gpdgc_iserver *server, unsigned long phase, 
        unsigned long round, unsigned short flags, gpdgc_message *message)
{
    g_assert(server->round_flags == 0);

    /* Check that there is at least one sender */
    gpdgc_process *local = server->local;
    int cmp_phase = gpdgc_cmp_counter(phase, local->phase);
    int cmp_round = gpdgc_cmp_counter(round, local->round);
    g_assert((cmp_phase > 0) || ((cmp_phase == 0) && (cmp_round >= 0)));

    local->phase = phase;
    local->round = round;
    local->step = 0;

    server->round_flags = GPDGC_ROUND_PENDING_FLAG;
    server->round_flags = server->round_flags | flags;
    return gpdgc_start_heardof_step(server, message);
}


/* Deliver a transport message to Heard-Of */
short is_in_a_reasonnable_futur(unsigned long reference_phase,
        unsigned long reference_round, unsigned long phase, unsigned round)
{
    if (phase == reference_phase)
    {
        return gpdgc_cmp_counter(round,
                reference_round + GPDGC_REASONNABLE_FUTUR_ROUND_THRESHOLD) < 0; 
    }
    return (gpdgc_cmp_counter(phase,
                reference_phase + GPDGC_REASONNABLE_FUTUR_PHASE_THRESHOLD) < 0)
        && (round < GPDGC_REASONNABLE_FUTUR_ROUND_THRESHOLD);
}
void gpdgc_process_past_decided_message(gpdgc_iserver *server,
        unsigned long phase, gpdgc_process *sender)
{
    /* Send the decision (if any) corresponding to the sender phase */
    if (gpdgc_cmp_counter(server->local->phase, phase) > 0)
    {
        /* Get decision and push the local clock and heardof type */
        gpdgc_message *fixed = gpdgc_get_decision(server, phase);
        if (fixed != NULL)
        {
            if (!gpdgc_build_heardof_message(server, fixed,
                        phase, 0, GPDGC_FIXED_STEP))
            {
                gpdgc_free_message(fixed);
                fixed = NULL;
            }
        }

        /* Send the decision */
        if (fixed != NULL)
        {
            gcry_sexp_t key = gpdgc_get_channel_key(server);
            size_t size = 0;
            void *buffer = gpdgc_write_contents(fixed, key, &size);
            gpdgc_free_message(fixed);

            if (buffer == NULL)
            {
                gpdgc_signal_lack_of_memory(server,
                        "%-10s: Decision '%lu:%lu:%d' cannot be buffered",
                        "HEARD_OF", phase, 0, GPDGC_FIXED_STEP);
            }
            else
            {
                g_debug("%-10s: Send decision '%lu:0:%d' to '%s'",
                        "HEARD_OF", phase, GPDGC_FIXED_STEP, sender->label);
                gpdgc_udp_send(server->socket, buffer, size, sender->address);
            }
            free(buffer);
        }
    }
}
void gpdgc_deliver_to_heardof(gpdgc_iserver *server,
        gpdgc_message *message, gpdgc_process *sender)
{
    /* Extract the clock from the message and update the sender clock */
    size_t phase_size;
    unsigned long *phase = gpdgc_pop_content(message, &phase_size);

    size_t round_size;
    unsigned long *round = gpdgc_pop_content(message, &round_size);

    size_t step_size;
    unsigned long *step = gpdgc_pop_content(message, &step_size);

    if ((phase_size != sizeof(unsigned long))
            || (round_size != sizeof(unsigned long))
            || (step_size != sizeof(unsigned long)))
    {
        g_info("%-10s: First three content of the message is not a clock!",
                "HEARD_OF");
        gpdgc_free_message(message);
        free(phase);
        free(round);
        free(step);
        return;      
    }
    
    /* Verify message clock */
    int cmp_sender_clock = gpdgc_cmp_clock(*phase, *round, *step,
                sender->phase, sender->round, sender->step);
    if (sender->state == GPDGC_INACTIVE)
    {
        if (cmp_sender_clock <= 0) 
        {
            g_info("%-10s: Ignore old message from old sender '%s'",
                    "HEARD_OF", sender->label);
            gpdgc_free_message(message);
            free(phase);
            free(round);
            free(step);
            return;
        }
    }
    else if (cmp_sender_clock > 0)
    {
        short phase_modified = sender->phase != *phase;
        sender->phase = *phase;
        sender->round = *round;
        sender->step = *step;
        g_debug("%-10s: Update '%s' clock to '%ld:%ld:%ld'", "HEARD_OF",
                sender->label, sender->phase, sender->round, sender->step);

        if (!sender->last_view_aware)
        {
            sender->last_view_aware = 1;
        }
        if (phase_modified)
        {
            gpdgc_clean_cache(server);
        }
    }

    /* Compute the expected message length and size */
    unsigned int nb_servers = g_slist_length(server->servers);
    unsigned int nb_clients = g_slist_length(server->clients);
    size_t max_msg_length = gpdgc_get_proposition_length(server->validation);
    size_t max_msg_size =
        gpdgc_get_proposition_size(nb_servers, nb_clients, server->validation);
    size_t item_cost = gpdgc_get_message_cost();
    if (gpdgc_has_certified_servers(server))
    {
        max_msg_length += *step == 0 ? 4 : 0;
        max_msg_size += GPDGC_MESSAGE_SIGNATURE_SIZE; 
        max_msg_size += 3 * sizeof(unsigned long);
        max_msg_size += 4 * item_cost;
    }
    if (*step > 0)
    {
        max_msg_length = nb_servers;
        max_msg_size = nb_servers * (item_cost + max_msg_size); 
    }

    /* Handle the message */
    int pending = server->round_flags & GPDGC_ROUND_PENDING_FLAG;
    gpdgc_process *local = server->local;
    int cmp_clock = gpdgc_cmp_clock(local->phase, local->round, local->step,
                                    *phase, *round, *step);
    if ((gpdgc_get_message_length(message) > max_msg_length) 
            || (gpdgc_get_message_size(message) > max_msg_size))
    {
        /* Ignore messages that are not well-formed */
        g_info("%-10s: Invalid message length (%u > %lu) or size (%lu > %lu)",
                "HEARD_OF", gpdgc_get_message_length(message), max_msg_length,
                gpdgc_get_message_size(message), max_msg_size);
        gpdgc_free_message(message);
    }
    else if ((message->contents != NULL) && (sender->state == GPDGC_ACTIVE)
            && (((*phase == local->phase) && (*step == GPDGC_FIXED_STEP)) 
                || ((cmp_clock == 0) && pending)))
    {
        /* Process the message being destinated to the current step */
        g_debug("%-10s: Received message '%lu:%lu:%lu' from '%s'",
                "HEARD_OF", *phase, *round, *step, sender->label);
        gpdgc_process_message(server, message, *step, sender);

        /* Check if the local state now allows to deliver the round messages */
        gpdgc_check_end_of_heardof_step(server);
    }
    else if ((message->contents != NULL) && (sender->state == GPDGC_ACTIVE)
            && ((cmp_clock == 0)
                || ((cmp_clock < 0)
                    && is_in_a_reasonnable_futur(local->phase, local->round,
                                                 *phase, *round))))
    {
        /* Cache the message; the message being destinated to a futur step */
        g_debug("%-10s: Received futur message '%lu:%lu:%lu'>='%lu:%lu:%lu' "
                "from '%s'", "HEARD_OF", *phase, *round, *step,
                local->phase, local->round, local->step, sender->label);
        gpdgc_cache_message(server, *phase, *round, *step, message, sender);
    }
    else 
    {
        if (*step != GPDGC_FIXED_STEP)
        {
            gpdgc_process_past_decided_message(server, *phase, sender);
        }
        gpdgc_free_message(message);
    }
    free(phase);
    free(round);
    free(step);
}
