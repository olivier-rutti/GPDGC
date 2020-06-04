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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "broadcast.h"
#include "consensus.h"
#include "process.h"


/* Broadcast container: create, compare and get */
int gpdgc_cmp_container(const void *void_first, const void *void_second)
{
    const gpdgc_container *first = void_first;
    const gpdgc_container *second = void_second;

    return gpdgc_cmp_counter(first->sequence_number, second->sequence_number);
}
gpdgc_container *gpdgc_get_container_from_list(GSList *list, unsigned long sn)
{
    GSList *iterator = list; 
    while (iterator != NULL)
    {
        gpdgc_container *message = iterator->data;
        iterator = iterator->next;

        if (sn == message->sequence_number)
        {
            return message;
        }      
    }
    return NULL; 
}
gpdgc_container *gpdgc_get_container(gpdgc_process *process, unsigned long sn)
{
    gpdgc_container *result =
        gpdgc_get_container_from_list(process->delivered_containers, sn);
    if (result == NULL)
    {
        result =
            gpdgc_get_container_from_list(process->undelivered_containers, sn);
    }
    return result;
}


/* Broadcast message of the specified type (reliable, ordered or view change) */
int gpdgc_broadcast_group_message(gpdgc_iserver *server,
        gpdgc_message *message, unsigned short type)
{
    int is_byzantine = gpdgc_is_byzantine_model(server);
    if ((type == GPDGC_RELIABLE_MESSAGE_TYPE)
            && is_byzantine
            && (server->validation == GPDGC_FULL_VALIDATION))
    {
        g_critical("%-10s: Cannot multicast message: rbroadcast is deactivated "
                "with byzantine failure and full consensus validation",
                "BROADCAST");
        gpdgc_free_message(message);
        return 0;
    }

    if (!gpdgc_push_content(message, &type, sizeof(unsigned short)))
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Cannot multicast message", "BROADCAST");
        gpdgc_free_message(message);
        return 0;
    }

    unsigned short flag = is_byzantine ? 0 : GPDGC_READY_MESSAGE_FLAG;
    struct sockaddr *origin = server->local->address;
    size_t addr_size = gpdgc_get_address_size(origin);
    size_t ul_size = sizeof(unsigned long);
    size_t us_size = sizeof(unsigned short);
    unsigned short msg_type = GPDGC_BROADCAST_MESSAGE_TYPE;
    if ((!gpdgc_push_content(message, &server->next_sequence_number, ul_size))
            || (!gpdgc_push_content(message, (void*)origin, addr_size))
            || (!gpdgc_push_content(message, &flag, us_size))
            || (!gpdgc_push_content(message, &msg_type, us_size)))
    {
        gpdgc_signal_lack_of_memory(server, 
                "%-10s: Cannot build message", "BROADCAST");
        gpdgc_free_message(message);
        return 0;
    }

    gcry_sexp_t key = gpdgc_get_channel_key(server);
    size_t size = 0;
    void *buffer = gpdgc_write_contents(message, key, &size);
    if (buffer == NULL)
    {
        gpdgc_signal_lack_of_memory(server, 
                "%-10s: Cannot buffer message", "BROADCAST");
        gpdgc_free_message(message);
        return 0;
    }

    g_debug("%-10s: Multicast initial %s message '%s:%lu' (type=%u)",
            "BROADCAST", is_byzantine ? "echo" : "ready", 
            server->local->label, server->next_sequence_number, type);
    gpdgc_reserve_slot(server, 1);
    server->next_sequence_number += 1;

    int result = gpdgc_udp_server_multicast(server, buffer, size);
    free(buffer);
    gpdgc_pop_content(message, NULL);
    gpdgc_deliver_to_broadcast(server, message, server->local);
    return result;
}


/* Send acknowledgment/received message */
void *gpdgc_build_ack_message(gpdgc_iserver *server, unsigned short flag,
        unsigned long *phase, unsigned long seq_number,
        gpdgc_process *origin, size_t *size)
{
    gpdgc_message *msg = gpdgc_create_message();
    size_t address_size = gpdgc_get_address_size(origin->address);
    size_t phase_size = phase != NULL ? sizeof(unsigned long) : 0;
    unsigned short type = GPDGC_ACK_MESSAGE_TYPE;
    unsigned short msg_type = GPDGC_BROADCAST_MESSAGE_TYPE;
    if ((msg == NULL)
            || (!gpdgc_push_content(msg, phase, phase_size)) 
            || (!gpdgc_push_content(msg, &type, sizeof(unsigned short)))
            || (!gpdgc_push_content(msg, &seq_number, sizeof(unsigned long)))
            || (!gpdgc_push_content(msg, (void*)origin->address, address_size))
            || (!gpdgc_push_content(msg, &flag, sizeof(unsigned short)))
            || (!gpdgc_push_content(msg, &msg_type, sizeof(unsigned short))))
    {
        gpdgc_free_message(msg);
        return NULL;
    }

    gcry_sexp_t key = gpdgc_get_channel_key(server);
    void *buffer = gpdgc_write_contents(msg, key, size);
    gpdgc_free_message(msg);

    return buffer;
}
int gpdgc_send_ack(gpdgc_iserver *server, unsigned short flag,
        unsigned long *phase, unsigned long seq_number, gpdgc_process *origin,
        gpdgc_process *dst)
{
    size_t size = 0;
    void *buffer = gpdgc_build_ack_message(server, flag, phase,
            seq_number, origin, &size);
    if (buffer == NULL)
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Unable to build ack for message '%s:%ld'",
                "BROADCAST", origin->label, seq_number);
        return 0;
    }

    g_debug("%-10s: Send ack for message '%s:%ld' to '%s'", "BROADCAST",
            origin->label, seq_number, dst->label);
    int result = gpdgc_udp_send(server->socket, buffer, size, dst->address);
    free(buffer);
    return result;
}
int gpdgc_send_phase_ack(gpdgc_iserver *server, gpdgc_process *origin,
        gpdgc_container *container, gpdgc_container_state *state)
{
    size_t size = 0;
    void *msg = gpdgc_build_ack_message(server, GPDGC_RECEIVED_MESSAGE_FLAG,
            &state->phase, container->sequence_number, origin, &size);
    if (msg == NULL)
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Unable to build phase-ack for message '%s:%ld'",
                "BROADCAST", origin->label, container->sequence_number);
        return 0;
    }
    container->phase_cache = msg;
    container->phase_size = size;

    g_debug("%-10s: Multicast phase-ack for message '%s:%ld'",
            "BROADCAST", origin->label, container->sequence_number);
    return gpdgc_udp_server_multicast(server, msg, size);
}


/* Send client reply */
int gpdgc_cmp_reply(const void *first, const void *second)
{
    const gpdgc_reply *first_reply = first;
    const gpdgc_reply *second_reply = second;

    return gpdgc_cmp_counter(first_reply->id, second_reply->id);
}
gpdgc_reply *gpdgc_create_reply(unsigned long id)
{
    gpdgc_reply *result = malloc(sizeof(gpdgc_reply));
    if (result != NULL)
    {
        result->id = id;
    }
    return result;
}
int gpdgc_send_client_reply(gpdgc_iserver *server, unsigned long id,
        void *message, size_t size, gpdgc_process *client)
{
    unsigned short type = GPDGC_CLIENT_REPLY_MESSAGE_TYPE;
    gpdgc_message *msg = gpdgc_create_message();
    if ((msg == NULL)
            || (!gpdgc_push_content(msg, message, size))
            || (!gpdgc_push_content(msg, &id, sizeof(unsigned long)))
            || (!gpdgc_push_content(msg, &type, sizeof(unsigned short))))
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Unable to build client reply", "BROADCAST");
        gpdgc_free_message(msg);
        return 0;
    }

    gpdgc_reply *reply = gpdgc_create_reply(id);
    reply->remaining_ticks = server->resend_period;
    if (reply == NULL)
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Unable to build client reply container", "BROADCAST");
        gpdgc_free_message(msg);
        return 0;
    }
    client->replies = g_slist_insert_sorted(client->replies,
            reply, gpdgc_cmp_reply);

    /* Clean the extraneous replies */
    if (g_slist_length(client->replies) > server->max_client_replies)
    {
        gpdgc_reply *first = client->replies->data;

        g_debug("%-10s: Remove reply '%s:%ld': too much reply in memory",
                "BROADCAST", client->label, first->id);
        client->replies = g_slist_remove(client->replies, first);
        gpdgc_free_reply(first);
    }

    gcry_sexp_t key = gpdgc_get_channel_key(server);
    reply->cache = gpdgc_write_contents(msg, key, &reply->size);
    gpdgc_free_message(msg);
    if (reply->cache == NULL)
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Unable to build client reply buffer", "BROADCAST");
        client->replies = g_slist_remove(client->replies, reply);
        return 0;
    }
    g_debug("%-10s: Send reply '%lu' to '%s'",
            "BROADCAST", reply->id, client->label);
    return gpdgc_udp_send(server->socket,
            reply->cache, reply->size, client->address);
}


/* Check coherency of messages, and send the required messages */
void gpdgc_process_vote(gpdgc_iserver *server, gpdgc_message *message,
        gpdgc_process *origin, gpdgc_container *container,
        gpdgc_container_state *state, int ready);
int gpdgc_build_content_cache(gpdgc_iserver *server, gpdgc_container *container,
        gpdgc_process *origin, gpdgc_message *msg, unsigned short flag)
{
    free(container->content_cache);
    container->content_cache = NULL;

    unsigned int length = gpdgc_get_message_length(msg);
    unsigned long sn = container->sequence_number;
    struct sockaddr *address = origin->address;
    size_t address_size = gpdgc_get_address_size(address);
    unsigned short msg_type = GPDGC_BROADCAST_MESSAGE_TYPE;
    if ((msg != NULL)
            && gpdgc_push_content(msg, &sn, sizeof(unsigned long))
            && gpdgc_push_content(msg, (void*)address, address_size)
            && gpdgc_push_content(msg, &flag, sizeof(unsigned short))
            && gpdgc_push_content(msg, &msg_type, sizeof(unsigned short)))
    {
        gcry_sexp_t key = gpdgc_get_channel_key(server);
        container->content_cache =
            gpdgc_write_contents(msg, key, &container->content_size);
        
        GSList *state_iterator = container->states;
        while (state_iterator != NULL)
        {
            gpdgc_container_state *state = state_iterator->data;
            state_iterator = state_iterator->next;

            state->last_container_resend = server->resend_period;
        }
    }
    else
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Cannot build cache of container '%s:%ld'",
                "BROADCAST", origin->label, container->sequence_number);
    }

    while (gpdgc_get_message_length(msg) > length)
    {
        gpdgc_pop_content(msg, NULL);
    }
    return container->content_cache != NULL;
}
void *gpdgc_build_empty_message(gpdgc_iserver *server, gpdgc_process *origin, 
        unsigned long sn, unsigned short type, int received, size_t *size)
{
    gpdgc_message *msg = gpdgc_create_message();
    size_t address_size = gpdgc_get_address_size(origin->address);
    unsigned short flag = received ? GPDGC_RECEIVED_MESSAGE_FLAG : 0;
    unsigned short msg_type = GPDGC_BROADCAST_MESSAGE_TYPE;
    if ((msg == NULL)
            || (!gpdgc_push_content(msg, &type, sizeof(unsigned short)))
            || (!gpdgc_push_content(msg, &sn, sizeof(unsigned long)))
            || (!gpdgc_push_content(msg, (void*)origin->address, address_size))
            || (!gpdgc_push_content(msg, &flag, sizeof(unsigned short)))
            || (!gpdgc_push_content(msg, &msg_type, sizeof(unsigned short))))
    {
        gpdgc_free_message(msg);
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Unable to build empty message '%s:%ld'",
                "BROADCAST", origin->label, sn);
        return 0;
    }

    gcry_sexp_t key = gpdgc_get_channel_key(server);
    void *buffer = gpdgc_write_contents(msg, key, size);
    gpdgc_free_message(msg);
    return buffer;
}
gpdgc_container_state *gpdgc_get_container_state(gpdgc_container *container,
        gpdgc_process *process)
{
    GSList *iterator = container != NULL ? container->states : NULL;
    while (iterator != NULL)
    {
        gpdgc_container_state *state = iterator->data;
        iterator = iterator->next;

        if (gpdgc_cmp_process(state->owner, process) == 0)
        {
            return state;
        }
    }
    return NULL;
}
void gpdgc_check_message_coherency(gpdgc_iserver *server, gpdgc_process *origin,
        gpdgc_container *container, gpdgc_container_state *state)
{
    if (state == NULL)
    {
        return;
    }
    g_assert(state->content != NULL);

    /* Count the number of received ACK/ECHO corresponding to the reference */
    unsigned int ack_counter = 0;
    unsigned int echo_counter = 0;
    unsigned int vote_counter = 0;
    GSList *iterator = container->states;
    while (iterator != NULL)
    {
        gpdgc_container_state *iterated = iterator->data;
        iterator = iterator->next;

        if ((iterated->content != NULL)
                && (gpdgc_cmp_message(iterated->content, state->content) == 0))
        {
             if (iterated->flags & GPDGC_READY_STATE_FLAG)
             {
                 ack_counter++;
             }
             else
             {
                 echo_counter++;
             }
        }
        vote_counter += iterated->content != NULL ? 1 : 0;
    }

    /* Rudeliver the container message when the ACK threshold is eached */
    int is_byzantine = gpdgc_is_byzantine_model(server);
    unsigned int nb_servers = g_slist_length(server->servers);
    unsigned int max_byzantine = gpdgc_get_max_byzantine(server);
    if (ack_counter >= (is_byzantine ? nb_servers - max_byzantine : 1))
    {
        unsigned short flag =
            GPDGC_READY_MESSAGE_FLAG | GPDGC_RECEIVED_MESSAGE_FLAG;
        if (gpdgc_build_content_cache(server, container, origin,
                    state->content, flag)) 
        {
            size_t us_size = 0;
            unsigned short *type = gpdgc_pop_content(state->content, &us_size);
            g_assert(us_size == sizeof(unsigned short));

            container->remaining_ticks = server->resend_period;
            container->flags |= GPDGC_COHERENT_CONTAINER_FLAG;
            container->content = state->content;
            container->content_type = *type;
            state->content = NULL;

            GSList *iterator = container->states;
            while (iterator != NULL)
            {
                gpdgc_container_state *state = iterator->data;
                iterator = iterator->next;

                gpdgc_free_message(state->content);
                state->content = NULL;
                if (gpdgc_cmp_process(server->local, state->owner) == 0)
                {
                    state->flags |= GPDGC_RECEIVED_STATE_FLAG;
                }
            }

            size_t buffer_size = 0;
            void *buffer = gpdgc_build_empty_message(server, origin,
                    container->sequence_number, *type, 1, &buffer_size);
            g_debug("%-10s: Multicast received for message '%s:%ld' (type=%d)",
                    "BROADCAST", origin->label, container->sequence_number,
                    container->content_type);
            gpdgc_udp_server_multicast(server, buffer, buffer_size);
            if (origin->type == GPDGC_CLIENT)
            {
                g_debug("%-10s: Send received for message '%s:%ld' (type=%d)",
                        "BROADCAST", origin->label, container->sequence_number,
                        container->content_type);
                gpdgc_udp_send(server->socket,
                        buffer, buffer_size, origin->address);
            }
            free(buffer);
            free(type);
        }
        return;
    }

    /* If the ack has already been sent, nothing more has to be done */
    if (container->flags & GPDGC_READY_CONTAINER_FLAG)
    {
        return;
    }

    /* Broadcast a ready message if we received 
     *   (1) a ready message from at least one correct server, or
     *   (2) an echo message from at least the half of the correct server */
    if ((ack_counter > max_byzantine)
            || (ack_counter + echo_counter > (nb_servers + max_byzantine) / 2))
    {
        gpdgc_message *clone = gpdgc_clone_message(state->content);
        unsigned short flag = GPDGC_READY_MESSAGE_FLAG;
        if ((clone != NULL)
                && gpdgc_build_content_cache(server, container, origin,
                    clone, flag)) 
        {
            g_debug("%-10s: Multicast ready message for '%s:%ld'",
                    "BROADCAST", origin->label, container->sequence_number);
            gpdgc_udp_server_multicast(server,
                    container->content_cache, container->content_size);
            container->remaining_ticks = server->resend_period;
            container->flags |= GPDGC_READY_CONTAINER_FLAG;

            gpdgc_container_state *local =
                gpdgc_get_container_state(container, server->local);
            gpdgc_process_vote(server, clone, origin, container, local, 1);
        }
        else
        {
            gpdgc_free_message(clone);
        }
        return;
    }

    /* If the echo has already been sent, nothing more has to be done */
    if (container->flags & GPDGC_INIT_CONTAINER_FLAG)
    {
        return;
    }

    /* Broadcast an echo message when we received 
     *   (1) an echo message from at least one correct server, or 
     *   (2) an echo or an ack message from the origin of the message */
    /* NB: The client message appears to be issued by local process */
    if ((gpdgc_cmp_process(state->owner, origin) == 0)
            || (ack_counter + echo_counter > max_byzantine))
    {
        gpdgc_message *clone = gpdgc_clone_message(state->content);
        if ((clone != NULL)
                && gpdgc_build_content_cache(server, container, origin,
                    clone, 0)) 
        {
            g_debug("%-10s: Multicast echo message for '%s:%ld'",
                    "BROADCAST", origin->label, container->sequence_number);
            gpdgc_udp_server_multicast(server,
                    container->content_cache, container->content_size);
            container->remaining_ticks = server->resend_period;
            container->flags |= GPDGC_INIT_CONTAINER_FLAG;

            gpdgc_container_state *local =
                gpdgc_get_container_state(container, server->local);
            gpdgc_process_vote(server, clone, origin, container, local, 0);
        }
        else
        {
            gpdgc_free_message(clone);
        }
        return;
    }

    /* Check that the threshold can be reached */
    if (vote_counter > (nb_servers - max_byzantine) / 2)
    {
        int max_counter = ack_counter + echo_counter;

        GSList *state_iterator = container->states;
        while (state_iterator != NULL)
        {
            gpdgc_container_state *iterated = state_iterator->data;
            state_iterator = state_iterator->next;

            if ((iterated->content != NULL) &&
                    (gpdgc_cmp_message(state->content, iterated->content) != 0))
            {
                int tmp_counter = 0;
                GSList *tmp_iterator = container->states;
                while (tmp_iterator != NULL)
                {
                    gpdgc_container_state *tmp = tmp_iterator->data;
                    tmp_iterator = tmp_iterator->next;

                    if (tmp->content != NULL)
                    {
                        tmp_counter += (gpdgc_cmp_message(iterated->content,
                                    tmp->content) == 0) ? 1 : 0;
                    }
                }
                
                max_counter = 
                    tmp_counter > max_counter ? tmp_counter : max_counter;
            }
        }

        if ((max_counter + nb_servers - vote_counter)
                <= ((nb_servers + max_byzantine) / 2))
        {
            g_critical("%-10s: Server '%s' is suspected to be byzantine",
                    "BROADCAST", origin->label);
            origin->suspiscion_flags |= GPDGC_BYZANTINE_FLAG;
            gpdgc_signal_event(server, GPDGC_SUSPISCION);
        }
    }
}


/* Create containers */
int gpdgc_add_container_state(gpdgc_container *container, gpdgc_process *owner)
{
    gpdgc_container_state *result = malloc(sizeof(gpdgc_container_state));
    if (result != NULL)
    {
        result->owner = owner;
        result->flags = 0;
        result->content = NULL;
        result->phase = 0;
        result->last_container_resend = container->remaining_ticks;

        container->states = g_slist_append(container->states, result);
    }
    return result != NULL;
}
gpdgc_container *gpdgc_create_container(gpdgc_iserver *server, 
        gpdgc_process *process, unsigned long sequence_number,
        unsigned short resend_period)
{
    gpdgc_container *result = malloc(sizeof(gpdgc_container));
    if (result != NULL)
    {
        result->sequence_number = sequence_number;
        result->flags = 0;
        result->states = NULL;
        result->remaining_ticks = resend_period;

        result->content= NULL;
        result->content_type = GPDGC_UNKNOWN_MESSAGE_TYPE;

        result->phase_cache = NULL;
        result->phase_size = 0;

        result->content_size = 0;
        result->content_cache = gpdgc_build_empty_message(server,
                process, sequence_number, GPDGC_ATOMIC_MESSAGE_TYPE, 0,
                &result->content_size);

        GSList *iterator = server->servers;
        while (iterator != NULL)
        {
            gpdgc_process *iterated = iterator->data;
            iterator = iterator->next;

            if (!gpdgc_add_container_state(result, iterated))
            {
                gpdgc_free_container(result);
                return NULL;
            }
        }

        process->undelivered_containers =
            g_slist_insert_sorted(process->undelivered_containers,
                    result, gpdgc_cmp_container);
        g_debug("%-10s: Create container '%s:%lu'",
                "BROADCAST", process->label, sequence_number);
    }
    return result;
}
int gpdgc_create_missing_containers(gpdgc_iserver *server, 
        gpdgc_process *process, unsigned long sequence_number)
{
    unsigned short resend_period = server->resend_period;
    unsigned long sn = process->sequence_number;
    while (gpdgc_cmp_counter(sn, sequence_number) <= 0)
    {
        gpdgc_container *container = gpdgc_get_container(process, sn);
        if (container == NULL)
        {
            container =
                gpdgc_create_container(server, process, sn, resend_period);
            if (container == NULL)
            {
                gpdgc_signal_lack_of_memory(server,
                        "%-10s: Unable to build missing container '%s:%lu'",
                        "BROADCAST", process->label, sn);
                return 0;
            }

            g_debug("%-10s: Require missing message '%s:%lu'",
                    "BROADCAST", process->label, sn);
            gpdgc_udp_server_multicast(server,
                    container->content_cache, container->content_size);

            if (process->type == GPDGC_CLIENT) 
            {
                gpdgc_container_state *local =
                    gpdgc_get_container_state(container, server->local);

                if (local->content == NULL)
                {
                    g_debug("%-10s: Require missing client message '%s:%lu'",
                            "BROADCAST", process->label, sn);
                    gpdgc_udp_send(server->socket, container->content_cache,
                            container->content_size, process->address);
                }
            }
        }
        sn++;
    }
    return 1;
}
gpdgc_container *gpdgc_create_container_on_reception(gpdgc_iserver *server,
    gpdgc_process *origin, unsigned long sn, int relaxed_test)
{
    if (gpdgc_cmp_counter(sn, origin->sequence_number) < 0)
    {
        g_info("%-10s: Ignore message '%s:%lu': container is not in memory",
                "BROADCAST", origin->label, sn);
        return NULL;
    }

    /* Check number of slot used by the origin process */
    unsigned long local_sn = origin->sequence_number;
    GSList *iterator = origin->delivered_containers;
    while (iterator != NULL)
    {
        gpdgc_container *container = iterator->data;
        iterator = iterator->next;

        if (gpdgc_cmp_counter(local_sn, container->sequence_number) < 0)
        {
            local_sn++;
        }
    }
    unsigned short multiplier = relaxed_test ? 3 : 2;
    if (gpdgc_cmp_counter(sn, local_sn + multiplier * server->max_slot) > 0)
    {
        g_info("%-10s: Ignore message '%s:%lu': limit of messages is reached",
                "BROADCAST", origin->label, sn);
        return NULL;
    }

    /* Check cache usage */
    if ((!relaxed_test) && (server->used_cache >= server->max_cache))
    {
        g_info("%-10s: Ignore message '%s:%lu': limit of cache is reached",
                "BROADCAST", origin->label, sn);
        return NULL;
    }

    /* Create containers for current (and all missing preceding) messages */
    if (!gpdgc_create_missing_containers(server, origin, sn - 1))
    {
        return NULL;
    }
    
    gpdgc_container *result =
        gpdgc_create_container(server, origin, sn, server->resend_period);
    if (result == NULL)
    {
        gpdgc_signal_lack_of_memory(server, "%-10s: Unable to build "
                "container '%s:%lu'", "BROADCAST", origin->label, sn);
    }
    return result;
}


/* Remove container from memory */
int gpdgc_is_delivered_by_all(gpdgc_container *container)
{
    int delivered_by_all = container->flags & GPDGC_DELIVERED_CONTAINER_FLAG;
    int rdeliver = container->content_type == GPDGC_RELIABLE_MESSAGE_TYPE;
    
    GSList *iterator = container->states;
    while ((iterator != NULL) && delivered_by_all)
    {
        gpdgc_container_state *state = iterator->data;
        iterator = iterator->next;

        delivered_by_all = (state->flags & GPDGC_RECEIVED_STATE_FLAG)
            && ((!rdeliver) || (state->flags & GPDGC_PHASED_STATE_FLAG));
    }
    return delivered_by_all;
}
void gpdgc_uncache_container(gpdgc_iserver *server, 
        gpdgc_process *origin, gpdgc_container *container)
{
    size_t container_size = gpdgc_get_message_size(container->content)
        + container->content_size + container->phase_size
        + sizeof(gpdgc_container);

    g_debug("%-10s: Remove container '%s:%ld' from memory (%ld)",
            "BROADCAST", origin->label, container->sequence_number,
            container_size);
    origin->delivered_containers =
        g_slist_remove(origin->delivered_containers, container);
    gpdgc_free_container(container);
    gpdgc_release_cache(server, container_size); 
}
void gpdgc_uncache_containers(gpdgc_iserver *server, gpdgc_process *origin)
{
    GSList *iterator = origin->delivered_containers;
    while (iterator != NULL)
    {
        gpdgc_container *container = iterator->data;
        int removable = gpdgc_cmp_counter(container->sequence_number,
                origin->sequence_number) < 0;

        iterator = removable ? iterator->next : NULL;
        if (removable && gpdgc_is_delivered_by_all(container))
        {
            gpdgc_uncache_container(server, origin, container);
        }
    }
}


/* Deliver containers */
unsigned long gpdgc_get_sequence_number(GSList **pointer, unsigned long start)
{
    unsigned long result = start;
    int loop = *pointer != NULL;
    while (loop)
    {
        gpdgc_container *container = (*pointer)->data;
        loop = 0;

        if (result == container->sequence_number)
        {
            result = container->sequence_number + 1;
        }
        if (gpdgc_cmp_counter(container->sequence_number, result) < 0)
        {
            *pointer = (*pointer)->next;
            loop = *pointer != NULL;
        }
    }
    return result;
}
void gpdgc_deliver_container(gpdgc_iserver *server, gpdgc_process *origin,
        gpdgc_container *container, int adelivered, GSList **sn_pointer)
{
    /* Process the delivery according to the message type */
    if (container->content_type == GPDGC_RELIABLE_MESSAGE_TYPE)
    {
        g_debug("%-10s: Rdeliver message '%s:%ld'", "BROADCAST",
                origin->label, container->sequence_number);

        gpdgc_message *delivered = gpdgc_clone_message(container->content);
        if (delivered == NULL)
        {
            gpdgc_signal_lack_of_memory(server,
                    "%-10s: Cannot rdeliver message '%s:%ld'",
                    "BROADCAST", origin->label, container->sequence_number);
            return;
        }
        gpdgc_deliver_broadcast_message(server, container->sequence_number, 
                container->content_type, delivered, origin);
    }
    else if (container->content_type == GPDGC_ATOMIC_MESSAGE_TYPE)
    {
        g_debug("%-10s: Adeliver message '%s:%ld'", "BROADCAST",
                origin->label, container->sequence_number);

        gpdgc_message *delivered = gpdgc_clone_message(container->content);
        if (delivered == NULL)
        {
            gpdgc_signal_lack_of_memory(server,
                    "%-10s: Cannot adeliver message '%s:%ld'",
                    "BROADCAST", origin->label, container->sequence_number);
            return;
        }
        gpdgc_deliver_broadcast_message(server, container->sequence_number, 
                container->content_type, delivered, origin);
    }
    else if (container->content_type == GPDGC_ADD_CLIENT_MESSAGE_TYPE)
    {
        g_debug("%-10s: Process add-client message '%s:%ld'", "BROADCAST",
                origin->label, container->sequence_number);

        struct sockaddr *address = gpdgc_peek_address(container->content, 0);
        g_assert(address != NULL);

        gpdgc_process *proc = gpdgc_get_process(server, address);
        if ((proc != NULL) && (proc->type == GPDGC_SERVER))
        {
            g_info("%-10s: Cannot add client '%s' (message '%s:%ld'): "
                    "it is already a server", "BROADCAST", proc->label,
                    origin->label, container->sequence_number);
        }
        else if ((proc != NULL) && (proc->type == GPDGC_CLIENT))
        {
            g_info("%-10s: Cannot add client '%s' (message '%s:%ld'): "
                    "it is already a client", "BROADCAST", proc->label,
                    origin->label, container->sequence_number);
        }
        else
        {
            gcry_sexp_t key = gpdgc_peek_gcry_sexp(container->content, 1);
            gpdgc_deliver_client_candidate_vote(server, address, key, origin);
        }
    }
    else if (container->content_type == GPDGC_ADD_SERVER_MESSAGE_TYPE)
    {
        g_debug("%-10s: Process add-server message '%s:%ld'", "BROADCAST",
                origin->label, container->sequence_number);

        struct sockaddr *address = gpdgc_peek_address(container->content, 0);
        g_assert(address != NULL);
        
        struct sockaddr *added = gpdgc_clone_address(address);
        if (added == NULL)
        {
            char *label = gpdgc_get_address_label(address);
            gpdgc_signal_lack_of_memory(server,
                    "%-10s: Cannot add '%s' specified in message '%s:%ld'",
                    "BROADCAST", label, origin->label,
                    container->sequence_number); 
            free(label);
            return;
        }
        gcry_sexp_t key = gpdgc_peek_gcry_sexp(container->content, 1); 
        server->server_candidates =
            g_slist_append(server->server_candidates, added);
        server->server_candidate_keys =
            g_slist_append(server->server_candidate_keys, key);
    }
    else if (container->content_type == GPDGC_REMOVE_CLIENT_MESSAGE_TYPE)
    {
        g_debug("%-10s: Process remove-client message '%s:%ld'", "BROADCAST",
                origin->label, container->sequence_number);

        struct sockaddr *address = gpdgc_peek_address(container->content, 0);
        g_assert(address != NULL);

        gpdgc_process *clt = gpdgc_get_process(server, address);
        if ((clt == NULL) ||
                (clt->type == GPDGC_SERVER) || (clt->state == GPDGC_INACTIVE))
        {
            char *label = gpdgc_get_address_label(address);
            g_info("%-10s: Cannot remove client '%s' (message '%s:%ld'): "
                    "client is not yet subscribed", "BROADCAST",
                    label, origin->label, container->sequence_number);
            free(label);
        }
        else
        {
            struct sockaddr *removed = gpdgc_clone_address(address);
            if (removed == NULL)
            {
                gpdgc_signal_lack_of_memory(server,
                        "%-10s: Cannot remove client '%s' (message '%s:%ld')",
                        "BROADCAST", clt->label, origin->label,
                        container->sequence_number); 
                return;
            }
            server->client_exclusions =
                g_slist_append(server->client_exclusions, removed);

            gpdgc_send_client_reply(server,
                    container->sequence_number, NULL, 0, clt);
        }
    }
    else if (container->content_type == GPDGC_REMOVE_SERVER_MESSAGE_TYPE)
    {
        g_debug("%-10s: Process remove-server message '%s:%ld'", "BROADCAST",
                origin->label, container->sequence_number);

        struct sockaddr *address = gpdgc_peek_address(container->content, 0);
        g_assert(address != NULL);

        gpdgc_process *srv = gpdgc_get_server(server, address);
        if (srv == NULL)
        {
            char *label = gpdgc_get_address_label(address);
            g_info("%-10s: Cannot remove server '%s' (message '%s:%ld'): "
                    "server is not in the view", "BROADCAST",
                    label, origin->label, container->sequence_number);
            free(label);
        }
        else
        {
            struct sockaddr *removed = gpdgc_clone_address(address);
            if (removed == NULL)
            {
                gpdgc_signal_lack_of_memory(server,
                        "%-10s: Cannot remove server '%s' (message '%s:%ld')",
                        "BROADCAST", srv->label, origin->label,
                        container->sequence_number); 
                return;
            }
            server->server_exclusions =
                g_slist_append(server->server_exclusions, removed);
        }
    }
    else if (container->content_type == GPDGC_UPDATE_TRUSTED_KEY_MESSAGE_TYPE)
    {
        g_debug("%-10s: Process update-key message '%s:%ld'", "BROADCAST",
                origin->label, container->sequence_number);

        unsigned size = gpdgc_get_content_size(container->content, 1);
        gcry_sexp_t new_key = gpdgc_peek_gcry_sexp(container->content, 1);
        if ((size == 0) || (new_key != NULL))
        {
            server->key_candidates =
                g_slist_append(server->key_candidates, new_key);
        }
        else
        {
            gpdgc_signal_lack_of_memory(server,
                    "%-10s: Cannot update the trusted key", "BROADCAST");
            return;
        }
    }
    else if (container->content_type == GPDGC_CLEAN_CACHE_MESSAGE_TYPE)
    {
        g_debug("%-10s: Process clean-cache message '%s:%ld'", "BROADCAST",
                origin->label, container->sequence_number);

        size_t phase_size;
        unsigned long *phase =
            gpdgc_peek_content(container->content, 0, &phase_size); 
        g_assert(phase_size == sizeof(unsigned long));

        gpdgc_deliver_clean_cache(server, *phase, origin);
    }
    else 
    {
        g_warning("%-10s: Message '%s:%ld' has invalid type '%u'", "BROADCAST",
                origin->label, container->sequence_number,
                container->content_type);
    }

    /* Update sequence number when container has been effectively delivered */
    int removable = origin->sequence_number == container->sequence_number;
    if (removable)
    {
        origin->sequence_number = gpdgc_get_sequence_number(sn_pointer,
                container->sequence_number + 1);
    }
    
    /* Indicate that the container is delivered */
    container->remaining_ticks = server->resend_period;
    container->flags = GPDGC_DELIVERED_CONTAINER_FLAG;
    container->delivery = server->next_phase + (adelivered ? -1 : 1);

    /* Remove the container from memory if no more needed or move it to cache */
    origin->undelivered_containers =
        g_slist_remove(origin->undelivered_containers, container);
    if (removable && gpdgc_is_delivered_by_all(container))
    {
        g_debug("%-10s: Remove container '%s:%ld' from memory",
                "BROADCAST", origin->label, container->sequence_number);
        gpdgc_free_container(container);
    }
    else
    {
        origin->delivered_containers = g_slist_insert_sorted(
                origin->delivered_containers, container, gpdgc_cmp_container);

        size_t container_size = gpdgc_get_message_size(container->content)
            + container->content_size + container->phase_size
            + sizeof(gpdgc_container);
        gpdgc_reserve_cache(server, container_size); 
    }

    /* Release local resources for flow control */
    if (gpdgc_cmp_process(server->local, origin) == 0)
    {
        gpdgc_release_slot(server, 1);
    }
}


/* Prepare a new consensus instance */
int gpdgc_requires_consensus(gpdgc_iserver *server, gpdgc_container *container)
{
    if (container->content_type == GPDGC_RELIABLE_MESSAGE_TYPE)
    {
        unsigned int missing = g_slist_length(server->servers);
        unsigned int max_faulty = gpdgc_get_max_faulty(server);
        if (server->election == GPDGC_ROTATING_COORDINATOR)
        {
            GSList *iterator = container->states;
            while ((iterator == NULL) && (missing > max_faulty))
            {
                gpdgc_container_state *state = iterator->data;
                iterator = iterator->next;

                missing -= (state->flags & GPDGC_COHERENT_STATE_FLAG) ? 1 : 0;
            }
        }
        return missing <= max_faulty;
    }
    return (container->content != NULL);
}
int gpdgc_is_rdeliverable(gpdgc_iserver *server, gpdgc_container *container)
{
    if ((container->content == NULL) 
            || (container->content_type != GPDGC_RELIABLE_MESSAGE_TYPE)
            || (!(container->flags & GPDGC_ORDERED_CONTAINER_FLAG)))
    {
        return 0;
    }

    int is_valid = server->election != GPDGC_ROTATING_COORDINATOR;
    unsigned int missing = g_slist_length(server->servers);
    unsigned long phase =
        server->local->phase - (server->current_decision != NULL ? 1 : 0);

    gpdgc_process *val = server->servers->data;
    GSList *iterator = container->states;
    while (iterator != NULL)
    {
        gpdgc_container_state *state = iterator->data;
        iterator = iterator->next;

        if ((state->flags & GPDGC_COHERENT_STATE_FLAG)
                && (gpdgc_cmp_counter(state->phase, phase) <= 0))
        {
            missing--;
            is_valid = is_valid || (gpdgc_cmp_process(state->owner, val) == 0);
        }
    }
    return is_valid && (missing <= gpdgc_get_max_faulty(server));
}
void gpdgc_prepare_consensus(gpdgc_iserver *server)
{
    g_assert(server->current_decision == NULL);
    g_assert(server->next_phase == server->local->phase);

    int nb_servers = g_slist_length(server->servers);
    int nb_clients = g_slist_length(server->clients);
    int proposal_size = (nb_servers + nb_clients) * sizeof(unsigned long);
    unsigned long *proposal = malloc(proposal_size);
    if (proposal == NULL)
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Cannot build consensus proposal", "BROADCAST");
        return;
    }

    unsigned int counter = 0;
    int requires_consensus = 0;
    GSList *processes = g_slist_copy(server->servers);
    processes = g_slist_concat(processes, g_slist_copy(server->clients));
    GSList *process_iterator = processes;
    while (process_iterator != NULL)
    {
        gpdgc_process *process = (gpdgc_process *) process_iterator->data;
        process_iterator = process_iterator->next;
        
        GSList *sn_pointer = process->delivered_containers;
        GSList *undelivered_iterator = process->undelivered_containers;
        proposal[counter] = process->sequence_number - 1;
        
        /* Deliver the messages to be delivered, and
         *  build the next consensus proposal for the current process */
        while (undelivered_iterator != NULL)
        {
            gpdgc_container *container = undelivered_iterator->data;
            undelivered_iterator = undelivered_iterator->next;
            unsigned long sn = container->sequence_number;

            /* Check that the container is the next deliverable container */
            proposal[counter] = gpdgc_get_sequence_number(&sn_pointer,
                    proposal[counter] + 1) - 1;
            if ((container->content != NULL) && (proposal[counter] == sn - 1))
            {
                proposal[counter] = sn; 

                /* Deliver the message when the conditions are satisfied */
                if (gpdgc_is_rdeliverable(server, container))
                {
                    gpdgc_deliver_container(server,
                            process, container, 0, &sn_pointer);
                }
                else
                {
                    unsigned long process_sn = process->sequence_number;
                    requires_consensus = requires_consensus 
                        || (gpdgc_requires_consensus(server, container)
                                && (gpdgc_cmp_counter(sn, process_sn) >= 0));
                }

                /* Update proposal */
                /* NB: container delivery may update process->sequence_number */ 
                int cmp = gpdgc_cmp_counter(process->sequence_number - 1, sn);
                proposal[counter] = cmp > 0 ? process->sequence_number - 1 : sn;
            }
        }

        /* Remove possibly obsolete containers from memory */
        gpdgc_uncache_containers(server, process);
        counter++;
    }
    g_slist_free(processes);

    /* Start a new consensus if new messages needed to be ordered */
    if (requires_consensus)
    {      
        char *proposal_label = gpdgc_get_vote_label(proposal, proposal_size);
        g_debug("%-10s: Propose '%s' at '%lu'", "BROADCAST", 
                proposal_label, server->next_phase);
        free(proposal_label);

        unsigned long phase = server->next_phase;
        server->next_phase++;
        if (gpdgc_start_consensus(server, phase, proposal))
        {
            return;
        }
        g_critical("%-10s: Start of consensus '%lu' fails", "BROADCAST", phase);
    }
    free(proposal);
}


/* Process undelivered coherent containers */
gpdgc_container_state *gpdgc_get_reference_state(gpdgc_container *container)
{
    /* Compute the occurences of each message in the container */
    GSList *states = NULL;
    GSList *counters = NULL;
    GSList *candidate_iterator = container->states;
    while (candidate_iterator != NULL)
    {
        gpdgc_container_state *candidate = candidate_iterator->data;
        candidate_iterator = candidate_iterator->next;

        if (candidate->content != NULL)
        {
            GSList *state_iterator = states;
            GSList *counter_iterator = counters;
            while ((state_iterator != NULL) && (counter_iterator != NULL)
                    && (gpdgc_cmp_message(candidate->content,
                            ((gpdgc_container_state *)
                             state_iterator->data)->content) != 0))
            {
                state_iterator = state_iterator->next;
                counter_iterator = counter_iterator->next;
            }

            if (state_iterator != NULL)
            {
                unsigned short *counter = counter_iterator->data;
                *counter = *counter + 1;
            }
            else
            {
                unsigned short *new_counter = malloc(sizeof(unsigned short));
                if (new_counter == NULL)
                {
                    g_slist_free(states);
                    g_slist_free_full(counters, free);
                    return NULL;
                }
                *new_counter = 1;
                states = g_slist_append(states, candidate);
                counters = g_slist_append(counters, new_counter);
            }
        }
    }

    /* Find and return the most frequent message */
    unsigned short max_counter = 0;
    gpdgc_container_state *result = NULL;
    GSList *state_iterator = states;
    GSList *counter_iterator = counters;
    while ((state_iterator != NULL) && (counter_iterator != NULL)) 
    {
        unsigned short *counter = counter_iterator->data;
        if (*counter > max_counter)
        {
            max_counter = *counter; 
            result = state_iterator->data;
        }
        state_iterator = state_iterator->next;
        counter_iterator = counter_iterator->next;
    }
    g_slist_free(states);
    g_slist_free_full(counters, free);
    return result;
}
void gpdgc_process_view_update(gpdgc_iserver *server, GSList *processes)
{
    if ((server->server_candidates == NULL)
            && (server->server_exclusions == NULL)
            && (server->client_candidates == NULL)
            && (server->client_exclusions == NULL))
    {
        return;
    }

    g_debug("%-10s: Deliver view change", "BROADCAST");
    gpdgc_apply_pending_view_changes(server);

    g_slist_free(server->server_candidates);
    server->server_candidates = NULL;
    g_slist_free(server->server_candidate_keys);
    server->server_candidate_keys = NULL;
    g_slist_free_full(server->server_exclusions, free);
    server->server_exclusions = NULL;
    g_slist_free_full(server->client_exclusions, free);
    server->client_exclusions = NULL;

    GSList *process_iterator = processes;
    while ((process_iterator != NULL) && (server->state == GPDGC_READY))
    {
        gpdgc_process *process = process_iterator->data;
        process_iterator = process_iterator->next;

        /* Update the states of undelivered containers */
        GSList *undelivered_iterator = process->undelivered_containers;
        while (undelivered_iterator != NULL)
        {
            gpdgc_container *undel = undelivered_iterator->data; 
            undelivered_iterator = undelivered_iterator->next;

            if (undel->content == NULL)
            {
                gpdgc_container_state *ref = gpdgc_get_reference_state(undel);
                gpdgc_check_message_coherency(server, process, undel, ref); 
            }
        }
    }
}
void gpdgc_process_trusted_key_update(gpdgc_iserver *server)
{
    GSList *key_update_iterator = server->key_candidates;
    while (key_update_iterator != NULL)
    {
        gcry_sexp_t new_key = key_update_iterator->data;
        key_update_iterator = key_update_iterator->next;

        unsigned long new_id = server->trusted_key_identifier + 1;
        gpdgc_set_trusted_key(server, new_key, new_id);
    }
    g_slist_free(server->key_candidates);
    server->key_candidates = NULL;
}
void gpdgc_process_undelivered_containers(gpdgc_iserver *server)
{
    unsigned int counter = 0;
    int possible_adeliver = server->current_decision != NULL;
    
    GSList *processes = g_slist_copy(server->servers);
    processes = g_slist_concat(processes, g_slist_copy(server->clients));
    GSList *process_iterator = processes;
    while (process_iterator != NULL)
    {
        gpdgc_process *process = (gpdgc_process *) process_iterator->data;
        process_iterator = process_iterator->next;
        
        GSList *seq_pointer = process->delivered_containers;
        GSList *undelivered_iterator = process->undelivered_containers;
        unsigned long next_sn = process->sequence_number;

        /* Deliver the messages to be delivered, and
         *  build the next consensus proposal for the current process */
        while (undelivered_iterator != NULL)
        {
            gpdgc_container *container = undelivered_iterator->data;
            undelivered_iterator = undelivered_iterator->next;

            next_sn = gpdgc_get_sequence_number(&seq_pointer, next_sn);
            unsigned long sn = container->sequence_number;
            if ((container->content != NULL) && (next_sn == sn))
            {
                short is_reliable =
                    container->content_type == GPDGC_RELIABLE_MESSAGE_TYPE; 

                /* Rudeliver container */
                if (!(container->flags & GPDGC_ORDERED_CONTAINER_FLAG))
                {
                    container->flags |= GPDGC_ORDERED_CONTAINER_FLAG;

                    gpdgc_container_state *state =
                        gpdgc_get_container_state(container, server->local);
                    g_assert(state != NULL);
                    state->phase = server->next_phase;
                    state->flags |= GPDGC_COHERENT_STATE_FLAG;

                    g_debug("%-10s: Rudeliver container '%s:%ld' "
                            "(type=%d, phase=%ld)", "BROADCAST", process->label,
                            sn, container->content_type, state->phase); 
                    if (is_reliable)
                    {
                        gpdgc_send_phase_ack(server, process, container, state);
                    }
                }

                /* Deliver the message when the conditions are satisfied */
                int adeliverable = possible_adeliver
                    && (gpdgc_cmp_counter(container->sequence_number,
                                server->current_decision[counter]) <= 0)
                    && (process->sequence_number == sn);
                int rdeliverable = gpdgc_is_rdeliverable(server, container);
                if (adeliverable || rdeliverable)
                {
                    gpdgc_deliver_container(server,
                            process, container, adeliverable, &seq_pointer);
                }

                /* Update next expected sequence number */
                /* NB: container delivery may update process->sequence_number */ 
                int cmp =
                    gpdgc_cmp_counter(process->sequence_number, next_sn + 1);
                next_sn = cmp > 0 ? process->sequence_number : next_sn + 1;
            }
        }

        /* Remove possibly obsolete containers from memory */
        gpdgc_uncache_containers(server, process);

        /* Require the missing messages for the current processes */
        if (server->current_decision != NULL)
        {
            if (!gpdgc_create_missing_containers(server, process, 
                        server->current_decision[counter]))
            {
                return;
            }

            possible_adeliver = possible_adeliver
                && (gpdgc_cmp_counter(process->sequence_number,
                            server->current_decision[counter]) > 0);
        }
        counter++;
    }

    /* After a decision has been fully processed, apply trusted key and
     *  server updates, and discard the decision */
    if (possible_adeliver)
    {
        gpdgc_process_trusted_key_update(server);
        gpdgc_process_view_update(server, processes);

        free(server->current_decision);
        server->current_decision = NULL;
    }
    g_slist_free(processes);

    /* Prepare a new consensus if no consensus is pending */
    if ((server->current_decision == NULL)
            && (server->next_phase == server->local->phase)
            && (server->state == GPDGC_READY))
    { 
        gpdgc_prepare_consensus(server);
    }
}


/* Process the specified decision of the specified phase */
void gpdgc_deliver_decision(gpdgc_iserver *server,
        unsigned long phase, unsigned long *values)
{
    g_assert(phase + 1 == server->next_phase);
    g_assert(server->current_decision == NULL);

    unsigned int nb_clients = g_slist_length(server->clients);
    unsigned int nb_servers = g_slist_length(server->servers);
    size_t proposal_size = (nb_servers + nb_clients) * sizeof(unsigned long);
    char *proposal_label = gpdgc_get_vote_label(values, proposal_size);
    g_debug("%-10s: Decided '%s' at '%lu'", "BROADCAST", proposal_label, phase);
    free(proposal_label);
    server->current_decision = values;
    gpdgc_process_undelivered_containers(server);
}


/* Check validity of network messages */
int gpdgc_check_ack(gpdgc_message* content, gpdgc_process *sender)
{
    unsigned int length = gpdgc_get_message_length(content); 
    size_t ack_size = gpdgc_get_content_size(content, 1);
    if (length != 2)
    {
        g_info("%-10s: Ignore ack message from '%s': invalid length (%d), "
               "expected %d", "BROADCAST", sender->label, length, 2);
        return 0;
    }
    else if ((ack_size != 0) && (ack_size != sizeof(unsigned long)))
    {
        g_info("%-10s: Ignore ack message from '%s': invalid size (%ld), "
               "expected %ld", "BROADCAST", sender->label, ack_size,
               sizeof(unsigned long));
        return 0;
    }
    return 1;
}
int gpdgc_check_broadcast_content(gpdgc_message* content, 
        gpdgc_process *sender, size_t max_size)
{
    unsigned int length = gpdgc_get_message_length(content); 
    size_t size = gpdgc_get_content_size(content, 1);
    if (length != 2)
    {
        g_info("%-10s: Ignore message from '%s': invalid length (%d), "
               "expected %d", "BROADCAST", sender->label, length, 2);
        return 0;
    }
    else if (size == 0)
    {
        g_info("%-10s: Ignore message from '%s': message is empty",
               "BROADCAST", sender->label);
        return 0;
    }
    else if (size > max_size)
    {
        g_info("%-10s: Ignore message from '%s': size %ld is greater than %ld",
               "BROADCAST", sender->label, size, max_size);
        return 0;
    }
    return 1;
}
int gpdgc_check_key_update(gpdgc_message *content, gpdgc_process *sender)
{
    unsigned int length = gpdgc_get_message_length(content); 
    size_t size = gpdgc_get_content_size(content, 1);

    if (length != 2)
    {
        g_info("%-10s: Ignore key update from '%s': invalid length (%d), "
               "expected %d", "BROADCAST", sender->label, length, 2);
        return 0;
    }
    else if (size > GPDGC_MAX_KEY_SIZE)
    {
        g_info("%-10s: Ignore key update from '%s': key size %ld > %d",
               "BROADCAST", sender->label, size, GPDGC_MAX_KEY_SIZE);
        return 0;
    }
    
    gcry_sexp_t key = gpdgc_peek_gcry_sexp(content, 1);
    if (key == NULL)
    {
        g_info("%-10s: Ignore key update from '%s': unreadable key",
               "BROADCAST", sender->label);
        return 0;
    }
    gcry_sexp_release(key);
    return 1;
}
int gpdgc_check_process_update(gpdgc_message *content, gpdgc_process *sender,
        int requires_key, int must_be_initiator)
{
    unsigned int length = gpdgc_get_message_length(content); 
    struct sockaddr *address = gpdgc_peek_address(content, 1);
    size_t size = gpdgc_get_content_size(content, 2);

    if (length != 3)
    {
        g_info("%-10s: Ignore process update from '%s': invalid length (%d), "
               "expected %d", "BROADCAST", sender->label, length, 3);
        return 0;
    }
    else if (address == NULL)
    {
        g_info("%-10s: Ignore process update from '%s': invalid address",
               "BROADCAST", sender->label);
        return 0;
    }
    else if (requires_key && (size > GPDGC_MAX_KEY_SIZE))
    {
        g_info("%-10s: Ignore key update from '%s': key size %ld > %d",
               "BROADCAST", sender->label, size, GPDGC_MAX_KEY_SIZE);
        return 0;
    }
    else if ((!requires_key) && (size != 0))
    {
        g_info("%-10s: Ignore process update from '%s': key is not necessary",
               "BROADCAST", sender->label);
        return 0;
    }
    else if (must_be_initiator
            && (gpdgc_cmp_address(sender->address, address) != 0))
    {
        char *label = gpdgc_get_address_label(address);
        g_info("%-10s: Ignore process update from '%s': the update of process "
                "'%s' should be initiated by itself if not trustly signed",
                "BROADCAST", sender->label, label);
        free(label);
        return 0;
    }

    int result = 1;
    gcry_sexp_t key = gpdgc_peek_gcry_sexp(content, 2);
    if (requires_key && (key == NULL))
    {
        g_info("%-10s: Ignore process update from '%s': unreadable key",
               "BROADCAST", sender->label);
        result = 0;
    }
    gcry_sexp_release(key);
    return result;
}
int gpdgc_check_clean_cache(gpdgc_message* content, gpdgc_process *sender)
{
    unsigned int length = gpdgc_get_message_length(content); 
    size_t phase_size = gpdgc_get_content_size(content, 1);
    if (length != 2)
    {
        g_info("%-10s: Ignore clean-cache message from '%s': invalid length "
                "(%d), expected %d", "BROADCAST", sender->label, length, 2);
        return 0;
    }
    else if (phase_size != sizeof(unsigned long))
    {
        g_info("%-10s: Ignore ack message from '%s': invalid size (%ld), "
               "expected %ld", "BROADCAST", sender->label, phase_size,
               sizeof(unsigned long));
        return 0;
    }
    return 1;
}
int gpdgc_check_broadcast_message(gpdgc_iserver *server, gpdgc_message* msg,
        gpdgc_process *sender, gpdgc_process *origin, int ready, int received)
{
    /* Retrieve the message type; the message is possibly signed */
    short has_been_signed = 0;
    if (gpdgc_get_content_size(msg, 0) != sizeof(unsigned short))
    {
        has_been_signed = 1; 
        if (!gpdgc_unsign_message(msg, server->trusted_key))
        {
            g_info("%-10s: Ignore message from '%s': wrong type size or "
                    " invalid signature", "BROADCAST", sender->label);
            return 0;
        }
    }

    /* Retreive message type */
    size_t type_size = 0;
    unsigned short *type = gpdgc_peek_content(msg, 0, &type_size);
    if (type_size != sizeof(unsigned short))
    {
        g_info("%-10s: Ignore message from '%s': unreadable type",
                "BROADCAST", sender->label);
        return 0;
    }
    unsigned int length = gpdgc_get_message_length(msg);

    /* Ignore non-initial messages coming from clients */
    if ((sender->type == GPDGC_CLIENT)
            && (gpdgc_cmp_process(origin, sender) != 0))
    {
        g_info("%-10s: Ignore message from client '%s': sender != origin",
                "BROADCAST", sender->label);
        return 0;
    }
    if ((sender->type == GPDGC_CLIENT) && received)
    {
        g_info("%-10s: Ignore message from client '%s': wrong flags",
                "BROADCAST", sender->label);
        return 0;
    }
    if ((sender->type == GPDGC_CLIENT) && (length == 1))
    {
        g_info("%-10s: Ignore message from client '%s': no content",
                "BROADCAST", sender->label);
        return 0;
    }
    int is_byzantine = gpdgc_is_byzantine_model(server);
    if ((sender->type == GPDGC_CLIENT) && is_byzantine && ready)
    {
        g_info("%-10s: Ignore message from client '%s': flagged ready",
                "BROADCAST", sender->label);
        return 0;
    }

    /* Ignore reliable messages with full validation and byzantine processes */
    if ((*type == GPDGC_RELIABLE_MESSAGE_TYPE)
            && is_byzantine && (server->validation == GPDGC_FULL_VALIDATION))
    {
        g_info("%-10s: Ignore rbroadcast message with byzantine failure and "
                "full consensus validation", "BROADCAST");
        return 0;
    }

    /* Ignore new messages from old servers/clients */
    if ((sender->state == GPDGC_INACTIVE) && received)
    {
        g_info("%-10s: Ignore message from old sender '%s': flagged received",
                "BROADCAST", sender->label);
        return 0;
    }
    if ((sender->state == GPDGC_INACTIVE) && (*type == GPDGC_ACK_MESSAGE_TYPE))
    {
        g_info("%-10s: Ignore ack message: sender '%s' is old",
                "BROADCAST", sender->label);
        return 0;
    }

    /* Ignore client messages with invalid type */
    if ((origin->type == GPDGC_CLIENT)
            && ((*type == GPDGC_CLEAN_CACHE_MESSAGE_TYPE)
                || (*type == GPDGC_ADD_CLIENT_MESSAGE_TYPE)))
    {
        g_info("%-10s: Ignore message from client '%s': the message "
                "types 'ack', 'clean-cache' or 'add-client' are forbidden",
                "BROADCAST", origin->label);
        return 0;
    }

    /* Ignore server messages with invalid type */
    if ((origin->type == GPDGC_SERVER)
            && ((*type == GPDGC_ADD_SERVER_MESSAGE_TYPE)
                || (*type == GPDGC_REMOVE_SERVER_MESSAGE_TYPE)
                || (*type == GPDGC_UPDATE_TRUSTED_KEY_MESSAGE_TYPE)
                || (*type == GPDGC_REMOVE_CLIENT_MESSAGE_TYPE)))
    {
        g_info("%-10s: Ignore message from server '%s': " "the message "
                "types 'add-server', 'remove-server', 'update-key', or "
                "'remove client' are forbidden", "BROADCAST", sender->label);
        return 0;
    }

    /* Ignore view messages that are not signed correctly */
    if ((sender->type == GPDGC_CLIENT)
            && ((*type == GPDGC_ADD_SERVER_MESSAGE_TYPE) 
                || (*type == GPDGC_REMOVE_SERVER_MESSAGE_TYPE) 
                || (*type == GPDGC_UPDATE_TRUSTED_KEY_MESSAGE_TYPE))
            && (server->trusted_key != NULL)
            && (!has_been_signed))
    {
        g_info("%-10s: Ignore view change from client '%s': the message has "
                "not been signed correctly", "BROADCAST", sender->label);
        return 0;
    }

    /* Ignore ack message with empty content */
    if (length == 1)
    {
        if (*type == GPDGC_ACK_MESSAGE_TYPE)
        {
            g_info("%-10s: Ignore ack message from '%s': no content",
                    "BROADCAST", sender->label); 
        }
        return *type != GPDGC_ACK_MESSAGE_TYPE;
    }

    int corrupted_channels = gpdgc_has_corrupted_channels(server);
    int certified_servers = gpdgc_has_certified_servers(server);
    size_t max_message_size = server->max_message_size;
    if (*type == GPDGC_ACK_MESSAGE_TYPE)
    {
        return gpdgc_check_ack(msg, sender);
    }
    else if ((*type == GPDGC_ATOMIC_MESSAGE_TYPE)
            || (*type == GPDGC_RELIABLE_MESSAGE_TYPE))
    {
        return gpdgc_check_broadcast_content(msg, sender, max_message_size);
    }
    else if (*type == GPDGC_UPDATE_TRUSTED_KEY_MESSAGE_TYPE)
    {
        return gpdgc_check_key_update(msg, sender);
    }
    else if (*type == GPDGC_ADD_SERVER_MESSAGE_TYPE)
    {
        int requires_key = corrupted_channels || certified_servers;
        return gpdgc_check_process_update(msg, sender, requires_key, 0);
    }
    else if (*type == GPDGC_ADD_CLIENT_MESSAGE_TYPE)
    {
        return gpdgc_check_process_update(msg, sender, corrupted_channels, 0);
    }
    else if (*type == GPDGC_REMOVE_SERVER_MESSAGE_TYPE)
    {
        return gpdgc_check_process_update(msg, sender, 0, 0);
    }
    else if (*type == GPDGC_REMOVE_CLIENT_MESSAGE_TYPE)
    {
        return gpdgc_check_process_update(msg, sender, 0,
                (sender->type == GPDGC_CLIENT) && (!has_been_signed));
    }
    else if (*type == GPDGC_CLEAN_CACHE_MESSAGE_TYPE)
    {
        return gpdgc_check_clean_cache(msg, sender);
    }
    g_info("%-10s: Ignore message: unknown type %u", "BROADCAST", *type);
    return 0;
}


/* Deliver a transport message to broadcast protocol */
void gpdgc_process_ack(gpdgc_iserver *server, gpdgc_message *message,
        gpdgc_process *origin, gpdgc_container *container,
        gpdgc_container_state *state, int received)
{
    if (received && (!(state->flags & GPDGC_PHASED_STATE_FLAG)))
    {
        state->flags |= GPDGC_PHASED_STATE_FLAG;
        g_debug("%-10s: Ack message '%s:%ld' has been received by '%s'",
                "BROADCAST", origin->label, container->sequence_number,
                state->owner->label);
    }

    size_t phase_size;
    unsigned long *phase = gpdgc_peek_content(message, 1, &phase_size);
    if ((state->flags & GPDGC_COHERENT_STATE_FLAG)
            || (phase_size != sizeof(unsigned long)))
    {
        return;
    }

    state->flags |= GPDGC_COHERENT_STATE_FLAG;
    state->phase = *phase;
    g_debug("%-10s: Received delivery phase of '%s' for message '%s:%ld'",
            "BROADCAST", state->owner->label, origin->label,
            container->sequence_number);

    gpdgc_container_state *local =
        gpdgc_get_container_state(container, server->local);
    g_assert(local != NULL);
    unsigned long *local_phase =
        local->flags & GPDGC_COHERENT_STATE_FLAG ? &local->phase : NULL;
    gpdgc_send_ack(server, GPDGC_RECEIVED_MESSAGE_FLAG, local_phase, 
            container->sequence_number, origin, state->owner);

    if (gpdgc_is_rdeliverable(server, container))
    {
        GSList *seq_pointer = origin->delivered_containers;
        gpdgc_deliver_container(server, origin, container, 0, &seq_pointer);
        gpdgc_uncache_containers(server, origin);
    }
    else if ((container->content != NULL)
            && (container->content_type == GPDGC_RELIABLE_MESSAGE_TYPE)
            && (server->current_decision == NULL)
            && (server->next_phase == server->local->phase))
    {
        gpdgc_prepare_consensus(server);
    }
}
int gpdgc_process_required(gpdgc_iserver *server, gpdgc_process *origin,
        gpdgc_container *container, gpdgc_process *sender, int ready)
{
    unsigned short flag =
        ready ? GPDGC_READY_CONTAINER_FLAG : GPDGC_INIT_CONTAINER_FLAG;
    if ((container->content == NULL) && (!(container->flags & flag)))
    {
        return 0;
    }

    gpdgc_container_state *state = gpdgc_get_container_state(container, sender);
    if ((state != NULL) && (container->content == NULL))
    {
        int diff = state->last_container_resend - container->remaining_ticks;
        if (diff < server->minimal_resend_period)
        {
            return 0;
        }
        state->last_container_resend = container->remaining_ticks;
    }

    g_debug("%-10s: Resend message '%s:%ld' to '%s'", "BROADCAST",
            origin->label, container->sequence_number, sender->label);
    return gpdgc_udp_send(server->socket,
            container->content_cache, container->content_size, sender->address);
}
void gpdgc_process_client_vote(gpdgc_iserver *server, gpdgc_message *message,
        gpdgc_process *origin, gpdgc_container *container, int ready)
{
    unsigned short flag = ready ? GPDGC_READY_MESSAGE_FLAG : 0; 
    size_t addr_size = gpdgc_get_address_size(origin->address);
    size_t ul_size = sizeof(unsigned long);
    size_t us_size = sizeof(unsigned short);
    unsigned short msg_type = GPDGC_BROADCAST_MESSAGE_TYPE;
    if ((!gpdgc_push_content(message, &container->sequence_number, ul_size))
            || (!gpdgc_push_content(message, (void*)origin->address, addr_size))
            || (!gpdgc_push_content(message, &flag, us_size))
            || (!gpdgc_push_content(message, &msg_type, us_size)))
    {
        gpdgc_signal_lack_of_memory(server, 
                "%-10s: Cannot build client message", "BROADCAST");
        gpdgc_free_message(message);
        return;
    }

    gcry_sexp_t key = gpdgc_get_channel_key(server);
    size_t size = 0;
    void *buffer = gpdgc_write_contents(message, key, &size);
    if (buffer == NULL)
    {
        gpdgc_signal_lack_of_memory(server, 
                "%-10s: Cannot buffer client message", "BROADCAST");
        gpdgc_free_message(message);
        return;
    }

    g_debug("%-10s: Forward client initial %s message '%s:%lu'",
            "BROADCAST", ready ? "ready" : "echo", 
            origin->label, container->sequence_number);
    gpdgc_udp_server_multicast(server, buffer, size);
    free(buffer);
    gpdgc_pop_content(message, NULL);
    gpdgc_deliver_to_broadcast(server, message, server->local);
}
void gpdgc_process_vote(gpdgc_iserver *server, gpdgc_message *message,
        gpdgc_process *origin, gpdgc_container *container,
        gpdgc_container_state *state, int ready)
{
    if (!(state->flags & GPDGC_READY_STATE_FLAG))
    {
        if (ready || ((state->content == NULL)
                    && (!(container->flags & GPDGC_READY_CONTAINER_FLAG))))
        {
            if (state->content != NULL)
            {
                gpdgc_free_message(state->content);
                state->content = NULL;
            }
            state->flags |= ready ? GPDGC_READY_STATE_FLAG : 0;
            state->content = message;

            g_debug("%-10s: Store %s message from '%s' in container '%s:%ld'",
                    "BROADCAST", ready ? "ready" : "echo", state->owner->label,
                    origin->label, container->sequence_number);
            gpdgc_check_message_coherency(server, origin, container, state);

            if (container->content != NULL)
            {
                gpdgc_process_undelivered_containers(server);
            }
            return;
        }
    }
    else
    {
        g_info("%-10s: Ignore message '%s:%ld': "
                "vote from '%s' has already been processed", "BROADCAST",
                origin->label, container->sequence_number, state->owner->label);
    }
    gpdgc_free_message(message);
}
void gpdgc_deliver_to_broadcast(gpdgc_iserver *server,
        gpdgc_message *message, gpdgc_process *sender)
{
    /* Only consider message with the right size */
    unsigned int message_length = gpdgc_get_message_length(message);
    if (message_length < 3)
    {
        g_info("%-10s: Ignore message from '%s': invalid length %d",
                "BROADCAST", sender->label, message_length);
        gpdgc_free_message(message);
        return;
    }

    size_t flags_size;
    unsigned short *flags = gpdgc_pop_content(message, &flags_size);  

    struct sockaddr *address = gpdgc_pop_address(message);

    size_t sn_size;
    unsigned long *sequence_number = gpdgc_pop_content(message, &sn_size);

    /* Only consider well-formed messages */
    if ((flags_size != sizeof(unsigned short))
            || (address == NULL)
            || (sn_size != sizeof(unsigned long)))
    {
        g_info("%-10s: Ignore message from '%s': invalid content => "
                "flag size %ld!=%ld, address is invalid, or sn size %ld!=%ld",
                "BROADCAST", sender->label, flags_size, sizeof(unsigned short),
                sn_size, sizeof(unsigned long));
        gpdgc_free_message(message);
        free(sequence_number);
        free(address);
        free(flags);
        return;
    }

    /* Retrieve origin: reject messages originated by unknown processes */
    gpdgc_process *origin = gpdgc_get_process(server, address);
    if (origin == NULL)
    {
        char *label = gpdgc_get_address_label(address);
        g_info("%-10s: Ignore message from '%s': unknown origin '%s'", 
               "BROADCAST", sender->label, label);
        gpdgc_free_message(message);
        free(sequence_number);
        free(address);
        free(flags);
        free(label);
        return;
    }
    free(address);

    /* Read the flags */
    int ready = (*flags & GPDGC_READY_MESSAGE_FLAG);
    int received = (*flags & GPDGC_RECEIVED_MESSAGE_FLAG);
    free(flags);

    /* Verify that the message is valid */
    if (!gpdgc_check_broadcast_message(server, message, sender, origin,
                ready, received)) 
    {
        gpdgc_free_message(message);
        free(sequence_number);
        return;
    }
    size_t msg_type_size;
    unsigned short *msg_type = gpdgc_peek_content(message, 0, &msg_type_size);
    g_assert(msg_type_size == sizeof(unsigned short));

    /* Retrieve the container for messages */
    gpdgc_container *container = gpdgc_get_container(origin, *sequence_number);
    if (container == NULL)
    {
        if ((sender->state == GPDGC_ACTIVE) && (origin->state == GPDGC_ACTIVE))
        {
            int relaxed_test = *msg_type == GPDGC_REMOVE_SERVER_MESSAGE_TYPE;
            container = gpdgc_create_container_on_reception(server, 
                    origin, *sequence_number, relaxed_test);
            if (container == NULL)
            {
                gpdgc_free_message(message);
                free(sequence_number);
                return;
            }
        }
        else 
        {
            if (!received)
            {
                g_info("%-10s: Ignore required message '%s:%ld': "
                        "the sender '%s' or the origin is old, "
                        "and cannot issue new message", "BROADCAST", 
                        origin->label, *sequence_number, sender->label);
            }
            gpdgc_free_message(message);
            free(sequence_number);
            return;
        }
    }
    free(sequence_number);

    /* Process client message */
    if ((sender->type == GPDGC_CLIENT) && (container->content != NULL))
    {
        size_t buffer_size = 0;
        void *buffer = gpdgc_build_empty_message(server, origin,
                container->sequence_number, *msg_type, 1, &buffer_size);
        g_debug("%-10s: Resend received for client message '%s:%ld'",
                "BROADCAST", origin->label, container->sequence_number);
        gpdgc_udp_send(server->socket, buffer, buffer_size, origin->address);
        free(buffer);
        gpdgc_free_message(message);
        return;
    }
    else if (sender->type == GPDGC_CLIENT)
    {
        gpdgc_process_client_vote(server, message, origin, container, ready);
        return;
    }

    /* Resend the local information about the message when required */
    if (!received) 
    {
        gpdgc_process_required(server, origin, container, sender, ready);
    }
    if (sender->state == GPDGC_INACTIVE)
    {
        gpdgc_free_message(message);
        return;
    }

    /* Process ack message */
    gpdgc_container_state *state = gpdgc_get_container_state(container, sender);
    g_assert(state != NULL);
    if (*msg_type == GPDGC_ACK_MESSAGE_TYPE)
    {
        gpdgc_process_ack(server, message, origin, container, state, received);
        gpdgc_free_message(message);

        int cmp = gpdgc_cmp_counter(container->sequence_number,
                origin->sequence_number);
        if ((cmp < 0) && gpdgc_is_delivered_by_all(container))
        {
            gpdgc_uncache_container(server, origin, container);
        }
        return;
    }

    /* Consider the message with received flag as received by the sender */
    if (received && (!(state->flags & GPDGC_RECEIVED_STATE_FLAG)))
    {
        state->flags |= GPDGC_RECEIVED_STATE_FLAG;
        g_debug("%-10s: Message '%s:%ld' has been received by '%s'",
                "BROADCAST", origin->label, container->sequence_number,
                state->owner->label);

        int cmp = gpdgc_cmp_counter(container->sequence_number,
                origin->sequence_number);
        if ((cmp < 0) && gpdgc_is_delivered_by_all(container))
        {
            gpdgc_uncache_container(server, origin, container);
            gpdgc_free_message(message);
            return;
        }
    }

    /* Check if the message allow to improve container coherency:
     *  store the message and check container coherency when it is the case */
    if ((container->content == NULL) && (gpdgc_get_message_length(message) > 1))
    {
        g_assert(origin->state == GPDGC_ACTIVE);
        gpdgc_process_vote(server, message, origin, container, state, ready);
        return;
    }
    gpdgc_free_message(message);
}
