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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "broadcast.h"
#include "common.h"
#include "consensus.h"
#include "process.h"

#define GPDGC_DEFAULT_INITIAL_SEQUENCE_NUMBER  0

#define GPDGC_NORMAL_PROCESS_PHASE_THRESHOLD   5 
#define GPDGC_SLOW_PROCESS_PHASE_THRESHOLD    10

/* Client candidate: create, cmp, free and remove */
gpdgc_client_candidate *gpdgc_create_client_candidate(struct sockaddr *client)
{
    gpdgc_client_candidate *result = malloc(sizeof(gpdgc_client_candidate));
    if (result != NULL)
    {
        result->client = gpdgc_clone_address(client);
        result->key = NULL;

        result->voters = NULL;
        result->keys = NULL;

        result->status = 0;
        result->remaining_ticks = 0;

        result->feedback = NULL;
        result->size = 0;
        if (result->client == NULL)
        {
            free(client);
            result = NULL;
        }
    }
    return result;
}
int gpdgc_cmp_client_candidate(const void *void_first, const void *void_second)
{
    const gpdgc_client_candidate *first = void_first;
    const gpdgc_client_candidate *second = void_second;

    return gpdgc_cmp_address(first->client, second->client);
}
void gpdgc_free_client_candidate(void *void_candidate)
{
    gpdgc_client_candidate *candidate = void_candidate;

    g_slist_free(candidate->voters);
    g_slist_free_full(candidate->keys, (void (*)(void *))gcry_sexp_release);

    gcry_sexp_release(candidate->key);
    free(candidate->feedback);
    free(candidate->client);
    free(candidate);
}

/* View candidate: create, compare and free */
gpdgc_view_candidate *gpdgc_create_view_candidate()
{
    gpdgc_view_candidate *result = malloc(sizeof(gpdgc_view_candidate));
    if (result != NULL)
    {
        result->servers = NULL;
        result->server_keys = NULL;
        result->server_seq_numbers = NULL;

        result->clients = NULL;
        result->client_keys = NULL;
        result->client_seq_numbers = NULL;

        result->phase = 0;
        result->view_identifier = 0;
        result->trusted_key_identifier = 0;
        result->trusted_key = NULL; 

        result->voters = NULL;
    }
    return result;
}
int gpdgc_cmp_address_list(GSList *first, GSList *second)
{
    GSList *fIterator = first;
    GSList *sIterator = second;
    while (fIterator != NULL)
    {
        if (sIterator == NULL)
        {
            return 1;
        }

        int cmp = gpdgc_cmp_address((struct sockaddr *) fIterator->data,
                (struct sockaddr *) sIterator->data);
        if (cmp != 0)
        {
            return cmp;
        }
        fIterator = fIterator->next;
        sIterator = sIterator->next;
    }
    if (sIterator != NULL)
    {
        return -1;
    }
    return 0;
}
int gpdgc_cmp_key_list(GSList *first, GSList *second, GError **exception)
{
    g_assert((exception == NULL) || (*exception == NULL));
    GError *cmp_exception = NULL;

    GSList *fIterator = first;
    GSList *sIterator = second;
    while (fIterator != NULL)
    {
        if (sIterator == NULL)
        {
            return 1;
        }

        int cmp = gpdgc_cmp_gcry_sexp_t((gcry_sexp_t) fIterator->data,
                (gcry_sexp_t) sIterator->data, &cmp_exception);
        if (cmp_exception != NULL)
        {
            g_propagate_error(exception, cmp_exception);
            return 1;
        }
        if (cmp != 0)
        {
            return cmp;
        }
        fIterator = fIterator->next;
        sIterator = sIterator->next;
    }
    if (sIterator != NULL)
    {
        return -1;
    }
    return 0;
}
int gpdgc_cmp_sn_list(GSList *first, GSList *second)
{
    GSList *fIterator = first;
    GSList *sIterator = second;
    while (fIterator != NULL)
    {
        if (sIterator == NULL)
        {
            return 1;
        }

        unsigned long *fsn = (unsigned long *) fIterator->data;
        unsigned long *ssn = (unsigned long *) sIterator->data;
        if (*fsn != *ssn)
        {
            return *fsn > *ssn ? 1 : -1;
        }
        fIterator = fIterator->next;
        sIterator = sIterator->next;
    }
    if (sIterator != NULL)
    {
        return -1;
    }
    return 0;
}
int gpdgc_cmp_view_candidate(gpdgc_view_candidate *first,
        gpdgc_view_candidate *second, GError **exception)
{
    g_assert((exception == NULL) || (*exception == NULL));

    int result = gpdgc_cmp_address_list(first->servers, second->servers);
    if (result != 0)
    {
        return result;
    }

    result = gpdgc_cmp_address_list(first->clients, second->clients);
    if (result != 0)
    {
        return result;
    }

    GError *cmp_exception = NULL;
    result = gpdgc_cmp_key_list(first->server_keys, second->server_keys,
            &cmp_exception);
    if (cmp_exception != NULL)
    {
        g_propagate_error(exception, cmp_exception);
        return 1;
    }
    if (result != 0)
    {
        return result;
    }

    result = gpdgc_cmp_key_list(first->client_keys, second->client_keys,
            &cmp_exception);
    if (cmp_exception != NULL)
    {
        g_propagate_error(exception, cmp_exception);
        return 1;
    }
    if (result != 0)
    {
        return result;
    }

    result = gpdgc_cmp_sn_list(first->server_seq_numbers,
            second->server_seq_numbers);
    if (result != 0)
    {
        return result;
    }

    result = gpdgc_cmp_sn_list(first->client_seq_numbers,
            second->client_seq_numbers);
    if (result != 0)
    {
        return result;
    }

    result = gpdgc_cmp_counter(first->phase, second->phase);
    if (result != 0)
    {
        return result;
    }

    result = gpdgc_cmp_counter(first->view_identifier, second->view_identifier);
    if (result != 0)
    {
        return result;
    }
    
    result = gpdgc_cmp_counter(first->trusted_key_identifier,
            second->trusted_key_identifier);
    if (result != 0)
    {
        return result;
    }

    result = gpdgc_cmp_gcry_sexp_t(first->trusted_key,
            second->trusted_key, &cmp_exception);
    if (cmp_exception != NULL)
    {
        g_propagate_error(exception, cmp_exception);
        return 1;
    }
    return result;
}
void gpdgc_free_view_candidate(void *void_candidate)
{
    gpdgc_view_candidate *candidate = void_candidate;

    g_slist_free_full(candidate->servers, free);
    g_slist_free_full(candidate->server_keys,
            (void (*)(void *)) gcry_sexp_release);
    g_slist_free_full(candidate->server_seq_numbers, free);

    g_slist_free_full(candidate->clients, free);
    g_slist_free_full(candidate->client_keys,
            (void (*)(void *)) gcry_sexp_release);
    g_slist_free_full(candidate->client_seq_numbers, free);

    g_slist_free_full(candidate->voters, free);
    gcry_sexp_release(candidate->trusted_key);
    free(candidate);
}


/* Remove from the cache everything that is no more needed to ensure that
 * each honest server in current view eventually delivers the messages sent */
int gpdgc_concern_previous_server(gpdgc_container *container)
{
    GSList *iterator = container->states;
    while (iterator != NULL)
    {
        gpdgc_container_state *state = iterator->data;
        iterator = iterator->next;

        if ((state->owner->state == GPDGC_INACTIVE)
                && ((!(state->flags & GPDGC_RECEIVED_STATE_FLAG))
                    || ((container->content_type == GPDGC_RELIABLE_MESSAGE_TYPE)
                        && (!(state->flags & GPDGC_PHASED_STATE_FLAG)))))
        {
            return 1;
        }
    }
    return 0;
}
size_t gpdgc_clean_containers(gpdgc_iserver *server,
        gpdgc_process *process, unsigned long reference)
{
    size_t result = 0;
    GSList *container_iterator = process->delivered_containers;
    while (container_iterator != NULL)
    {
        gpdgc_container *container = container_iterator->data;
        container_iterator = container_iterator->next;

        unsigned long retention = reference;
        if (gpdgc_concern_previous_server(container))
        {
            retention -= server->max_retention_cache;
        }

        if ((gpdgc_cmp_counter(process->sequence_number,
                        container->sequence_number) > 0)
                && (gpdgc_cmp_counter(retention, container->delivery) > 0))
        {
            size_t container_size = gpdgc_get_message_size(container->content)
                + container->content_size + container->phase_size
                + sizeof(gpdgc_container);
            
            g_debug("%-10s: Remove container '%s:%ld' from memory (%ld)",
                    "PROCESS", process->label, container->sequence_number,
                    container_size);
            result += container_size;

            process->delivered_containers =
                g_slist_remove(process->delivered_containers, container);
            gpdgc_free_container(container);
        }
    }
    return result;
}
void gpdgc_clean_cache(gpdgc_iserver *server)
{
    GSList *phases = NULL;
    GSList *process_iterator = server->servers;
    while (process_iterator != NULL)
    {
        gpdgc_process *process = (gpdgc_process *) process_iterator->data;
        process_iterator = process_iterator->next;

        phases = g_slist_insert_sorted(phases, &process->phase,
                (int (*)(const void *, const void *))gpdgc_cmp_counter_pointer);
    }
    unsigned int nb_phases = g_slist_length(phases);
    unsigned long smallest = *(unsigned long *) phases->data;
    unsigned long retention = smallest - server->max_retention_cache;
    unsigned long reference_speed_phase = 
        *(unsigned long *) g_slist_nth(phases, nb_phases / 2)->data;
    g_slist_free(phases);
    if (gpdgc_cmp_counter(retention, server->local->removal_phase) > 0)
    {
        server->local->removal_phase = retention;
    }

    process_iterator = server->servers;
    while (process_iterator != NULL)
    {
        gpdgc_process *process = (gpdgc_process *) process_iterator->data;
        process_iterator = process_iterator->next;

        if (gpdgc_cmp_counter(reference_speed_phase,
                    process->phase + GPDGC_SLOW_PROCESS_PHASE_THRESHOLD) >= 0)
        {
            if (!(process->suspiscion_flags & GPDGC_CRASHED_FLAG))
            {
                g_warning("%-10s: Process '%s' is suspected to be slow",
                        "PROCESS", process->label);

                process->suspiscion_flags |= GPDGC_CRASHED_FLAG;
                gpdgc_signal_event(server, GPDGC_SUSPISCION);
            }
        }
        else if (gpdgc_cmp_counter(reference_speed_phase,
                    process->phase + GPDGC_NORMAL_PROCESS_PHASE_THRESHOLD) < 0)
        {
            process->suspiscion_flags &=
                (unsigned short)(0 - GPDGC_CRASHED_FLAG); 
        }

        size_t released = gpdgc_clean_containers(server, process, smallest);
        gpdgc_release_cache(server, released);
    }

    process_iterator = server->clients;
    while (process_iterator != NULL)
    {
        gpdgc_process *process = (gpdgc_process *) process_iterator->data;
        process_iterator = process_iterator->next;

        size_t released = gpdgc_clean_containers(server, process, smallest);
        gpdgc_release_cache(server, released);
    }

    process_iterator = server->previouses;
    while (process_iterator != NULL)
    {
        gpdgc_process *process = (gpdgc_process *) process_iterator->data;
        process_iterator = process_iterator->next;

        size_t released = gpdgc_clean_containers(server, process, smallest);
        gpdgc_release_cache(server, released);
    }

    GSList* decision_iterator = server->previous_decisions;
    while (decision_iterator != NULL)
    {
        gpdgc_timed_vote *decision = decision_iterator->data; 
        decision_iterator = decision_iterator->next;

        if (gpdgc_cmp_counter(decision->timestamp, retention) < 0)
        {
            g_debug("%-10s: Remove decision of phase '%ld'",
                    "PROCESS", decision->timestamp);
            server->previous_decisions =
                g_slist_remove(server->previous_decisions, decision);
            gpdgc_release_cache(server,
                    sizeof(gpdgc_timed_vote) + decision->size + sizeof(GSList)); 
            gpdgc_free_timed_vote(decision);
        }
    }
}

/* Compare the specified process */
int gpdgc_cmp_process(gpdgc_process *first, gpdgc_process *second)
{
    return gpdgc_cmp_address(first->address, second->address);
}

/* Create the process corresponding to the specified address */
gpdgc_process *gpdgc_create_process(struct sockaddr *address,
        gpdgc_process_type type, gcry_sexp_t public_key, 
        unsigned long sequence_number)
{
    if ((address->sa_family != AF_INET) && (address->sa_family != AF_INET6))
    {
        return NULL;
    }

    gpdgc_process *result = malloc(sizeof(gpdgc_process));
    if (result == NULL)
    {
        return NULL;
    }

    result->label = gpdgc_get_address_label(address);
    if (result->label == NULL)
    {
        free(result);
        return NULL;
    }

    result->current = NULL;
    if (type == GPDGC_SERVER)
    {
        result->current = malloc(sizeof(gpdgc_round));
        if (result->current == NULL)
        {
            free(result);
            return NULL;
        }
        result->current->flags = 0;
        result->current->message = NULL;
        result->current->decision = NULL;
        result->current->counter = 0;
        result->current->votes = NULL;
    }

    result->address = address;
    result->type = type;
    result->state = GPDGC_ACTIVE;
    result->public_key = public_key;
    result->phase = 0;
    result->round = 0;
    result->step = 0;
    result->suspiscion_flags = 0;
    result->futures = NULL;
    result->replies = NULL;
    result->sequence_number = sequence_number;
    result->delivered_containers = NULL;
    result->undelivered_containers = NULL;
    result->last_view_aware = 0;
    result->excluded_from_view = 0;
    result->removal_phase = 0;
    return result;
}

/* Get the process/server corresponding to the specified process address */
gpdgc_process *gpdgc_do_get_process(GSList *processes, struct sockaddr *address)
{
    GSList *iterator = processes;
    while (iterator != NULL)
    {
        gpdgc_process *iterated = iterator->data;
        if (gpdgc_cmp_address(address, iterated->address) == 0)
        {
            return iterated;
        }
        iterator = iterator->next;
    }
    return NULL;
}
gpdgc_process *gpdgc_get_process(gpdgc_iserver *server, struct sockaddr *address)
{
    gpdgc_process *result = gpdgc_do_get_process(server->servers, address);
    if (result == NULL)
    {
        result = gpdgc_do_get_process(server->clients, address);
    }
    if (result == NULL)
    {
        result = gpdgc_do_get_process(server->previouses, address);
    }    
    return result;
}
gpdgc_process *gpdgc_get_server(gpdgc_iserver *server, struct sockaddr *address)
{
    return gpdgc_do_get_process(server->servers, address);
}


/* Find a process that is synchronized with the distributed clock */
GSList *gpdgc_get_soon_removed(gpdgc_iserver *server)
{
    GSList *result = NULL;
    GSList *client_iterator = server->clients;
    while (client_iterator != NULL)
    {
        gpdgc_process *client = client_iterator->data;
        client_iterator = client_iterator->next;

        GSList *container_iterator = client->undelivered_containers;
        while (container_iterator != NULL)
        {
            gpdgc_container *container = container_iterator->data;
            container_iterator = container_iterator->next;

            if ((container->content_type == GPDGC_REMOVE_SERVER_MESSAGE_TYPE)
                    && (container->flags & GPDGC_ORDERED_CONTAINER_FLAG))
            {
                struct sockaddr *rm = gpdgc_peek_address(container->content, 0);
                result = g_slist_append(result, rm);
            }
        }
    }
    return result;
}
gpdgc_process *gpdgc_get_synchronized_server(gpdgc_iserver *server)
{
    // NB: Synchronizing on the biggest group as possible improves performance,
    //      especially in the case of big differences in process speeds
    //     This explains why synchronisation is made on n-b processes, where n
    //      is the number of servers excluding those that will be soon removed,
    //      instead of 2b+1 processes as suggested in paper [DLS 88]
    unsigned int max_faulty = gpdgc_get_max_faulty(server);
    unsigned int quorum = 0;
    GSList *soon_removed = NULL;
    if (gpdgc_is_byzantine_model(server))
    {
        quorum = g_slist_length(server->servers) - max_faulty - 1;
        soon_removed = gpdgc_get_soon_removed(server);
    }

    gpdgc_process *result = NULL;
    GSList *tmp_iterator = server->servers;
    while (tmp_iterator != NULL)
    {
        gpdgc_process *tmp = tmp_iterator->data;
        tmp_iterator = tmp_iterator->next;

        if ((result == NULL) 
                || (gpdgc_cmp_clock(tmp->phase, tmp->round, tmp->step,
                        result->phase, result->round, result->step) > 0)) 
        {
            unsigned int synchronized_count = 0;
            GSList *cmp_iterator = server->servers;
            while (cmp_iterator != NULL)
            {
                gpdgc_process *cmp = cmp_iterator->data;
                cmp_iterator = cmp_iterator->next;

                if ((gpdgc_cmp_clock(tmp->phase, tmp->round, tmp->step,
                                cmp->phase, cmp->round, cmp->step) <= 0)
                        || gpdgc_contains_address(soon_removed, cmp->address))
                {
                    synchronized_count ++; 
                }
            }

            if (synchronized_count > quorum)
            {
                result = tmp;
            }
        }
    }
    g_slist_free(soon_removed);
    return result;
}


/* Multicast the specified message to other servers */
int gpdgc_udp_client_multicast(gpdgc_iserver *server, void *msg, size_t size)
{
    int result = 1;
    GSList *iterator = server->clients;
    while ((iterator != NULL) && result)
    {
        gpdgc_process *dst = iterator->data;
        iterator = iterator->next;

        if (msg != NULL)
        {
            result = gpdgc_udp_send(server->socket, msg, size, dst->address);
        }
    }
    return result;
}


/* Multicast the specified message to other servers */
int gpdgc_udp_server_multicast(gpdgc_iserver *server, void *msg, size_t size)
{
    int result = 1;
    GSList *iterator = server->servers;
    while ((iterator != NULL) && result)
    {
        gpdgc_process *dst = iterator->data;
        iterator = iterator->next;

        if ((gpdgc_cmp_process(dst, server->local) != 0) && (msg != NULL))
        {
            result = gpdgc_udp_send(server->socket, msg, size, dst->address);
        }
    }
    return result;
}


/* Clean the candidates when the limit is reached as follows; remove the oldest
 *  rejected candidate or the least popular candidate of the process,
 *  among those with many candidates, that issues the least recent candidate */
// NB: since they are a-delivered, the same candidate is removed everywhere 
int gpdgc_send_candidate_feedback(gpdgc_iserver *server,
        gpdgc_client_candidate *candidate, unsigned short type) 
{
    gpdgc_message *msg = gpdgc_create_message();
    if ((msg == NULL)
            || (!gpdgc_push_content(msg, &type, sizeof(unsigned short))))
    {
        gpdgc_free_message(msg);
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Client subscription feedback cannot be build",
                "PROCESS");
        return 0;
    }

    gcry_sexp_t key = gpdgc_get_channel_key(server);
    candidate->feedback = gpdgc_write_contents(msg, key, &candidate->size);
    candidate->remaining_ticks = server->resend_period;
    gpdgc_free_message(msg);

    if (candidate->feedback == NULL)
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Client subscription feedback cannot be buffered",
                "PROCESS");
        return 0;
    }

    char *label = gpdgc_get_address_label(candidate->client);
    g_debug("%-10s: Send feedback '%s' to client '%s'", "PROCESS",
            type == GPDGC_ACK_SUBSCRIPTION_MESSAGE_TYPE ? "OK" : "NOK", label);
    free(label);
    return gpdgc_udp_send(server->socket,
            candidate->feedback, candidate->size, candidate->client);
}
void gpdgc_remove_client_candidate(gpdgc_iserver *server, 
        gpdgc_client_candidate *candidate)
{
    server->client_candidates =
        g_slist_remove(server->client_candidates, candidate);
    gpdgc_free_client_candidate(candidate);
}
void gpdgc_clean_client_candidates(gpdgc_iserver *server)
{
    gpdgc_client_candidate *remove = NULL;
    GSList *candidate_iterator = server->client_candidates;
    while ((candidate_iterator != NULL) && (remove == NULL))
    {
        gpdgc_client_candidate *candidate = candidate_iterator->data;
        candidate_iterator = candidate_iterator->next;

        remove = candidate->status == 3 ? candidate : NULL;

        GSList *inner_iterator = remove == NULL ? candidate_iterator : NULL;
        while (inner_iterator != NULL)
        {
            gpdgc_client_candidate *inner = inner_iterator->data;
            inner_iterator = inner_iterator->next;

            int common_voter = 0;
            GSList *proposer_iterator = candidate->voters;
            while ((proposer_iterator != NULL) && (!common_voter))
            {
                struct sockaddr *proposer = proposer_iterator->data;
                proposer_iterator = proposer_iterator->next;

                common_voter = gpdgc_contains_address(inner->voters, proposer);
            }

            if (common_voter && (remove == NULL))
            {
                remove = candidate;
            }
            if (common_voter
                    && (g_slist_length(inner->voters)
                        < g_slist_length(remove->voters)))
            {
                remove = inner;
            }
        }
    }
    remove = remove == NULL ? server->client_candidates->data : remove;
    remove->status = 3;
    gpdgc_send_candidate_feedback(server,
            remove, GPDGC_NACK_SUBSCRIPTION_MESSAGE_TYPE);

    char *label = gpdgc_get_address_label(remove->client);
    g_debug("%-10s: Refuse client '%s'", "PROCESS", label);
    free(label);
    gpdgc_remove_client_candidate(server, remove);
}


/* Methods to manager client candidates: get, clean, remove */
gpdgc_client_candidate *gpdgc_get_client_candidate(gpdgc_iserver *server,
        struct sockaddr *address)
{
    GSList *candidate_iterator = server->client_candidates;
    while (candidate_iterator != NULL)
    {
        gpdgc_client_candidate *candidate = candidate_iterator->data;
        candidate_iterator = candidate_iterator->next;

        if (gpdgc_cmp_address(address, candidate->client) == 0)
        {
            return candidate;
        }
    }

    int nb_servers = g_slist_length(server->servers);
    unsigned int max_candidates =
        server->max_clients > nb_servers ? server->max_clients : nb_servers;

    gpdgc_client_candidate *result = gpdgc_create_client_candidate(address);
    if (result == NULL)
    {
        return result;
    }
    while (g_slist_length(server->servers) + 1 > max_candidates)
    {
        gpdgc_clean_client_candidates(server);
    }

    server->client_candidates = g_slist_insert_sorted(server->client_candidates,
            result, gpdgc_cmp_client_candidate);
    pthread_cond_broadcast(&server->client_condition);
    return result;
}


/* Broadcast client candidate */
int gpdgc_broadcast_client_subscription(gpdgc_iserver *server, 
        gpdgc_client_candidate *candidate)
{
    size_t sender_size = gpdgc_get_address_size(candidate->client);
    gpdgc_message *add_msg = gpdgc_create_message();
    if ((add_msg == NULL)
            || (!gpdgc_push_gcry_sexp(add_msg, candidate->key))
            || (!gpdgc_push_content(add_msg, candidate->client, sender_size)))
    {
        gpdgc_free_message(add_msg);
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Client subscription cannot be processed", "PROCESS");
        return 0;
    }

    int result = 0;
    char *label = gpdgc_get_address_label(candidate->client);
    g_debug("%-10s: The subscription from client '%s' has been broadcasted",
            "PROCESS", label);
    if (!gpdgc_broadcast_group_message(server, add_msg, 
                GPDGC_ADD_CLIENT_MESSAGE_TYPE))
    {
        g_warning("%-10s: An error occurs while sending subscription of '%s'",
                "PROCESS", label);
    }
    else
    {
        gpdgc_send_candidate_feedback(server,
                candidate, GPDGC_ACK_SUBSCRIPTION_MESSAGE_TYPE); 
        result = 1;
    }
    free(label);
    return result; 
}


/* Initiate client candidate */
void gpdgc_initiate_client_candidate(gpdgc_iserver *server,
        gpdgc_message *message, struct sockaddr *sender)
{
    size_t size;
    void *buffer = gpdgc_pop_content(message, &size);
    gcry_sexp_t key = NULL;
    if ((size > 0) && gcry_sexp_new(&key, buffer, size, 0))
    {
        char *label = gpdgc_get_address_label(sender);
        g_info("%-10s: The subscription from client '%s' is ignored: "
                "key cannot be read from message", "PROCESS", label);
        gpdgc_free_message(message);
        free(buffer);
        free(label);
        return;
    }
    free(buffer);

    int corrupted = gpdgc_has_corrupted_channels(server);
    if ((corrupted && (key == NULL)) || ((!corrupted) && (key != NULL)))
    {
        char *label = gpdgc_get_address_label(sender);
        g_info("%-10s: The subscription from client '%s' is ignored: "
                "key is required only and only if channels are corrupted",
                "PROCESS", label);
        gpdgc_free_message(message);
        gcry_sexp_release(key);
        free(label);
        return;
    }

    char *label = gpdgc_get_address_label(sender);
    gpdgc_client_candidate *candidate =
        gpdgc_get_client_candidate(server, sender);
    if (candidate->status != 0)
    {
        g_info("%-10s: Client subscription from '%s' is ignored: "
                "subscription has been already processed", "PROCESS", label);
        gcry_sexp_release(key);
    }
    else
    {
        g_debug("%-10s: Client subscription from '%s' is initiated", 
                "PROCESS", label);
        candidate->status = 1;
        candidate->key = key;
    }
    free(label);
    gpdgc_free_message(message);
}


/* Deliver vote for client candidate */
void gpdgc_deliver_client_candidate_vote(gpdgc_iserver *server,
        struct sockaddr *address, gcry_sexp_t key, gpdgc_process *voter)
{
    gpdgc_process *clt = gpdgc_do_get_process(server->clients, address);
    if (clt != NULL)
    {
        g_info("%-10s: Ignore client candidate: '%s' is already a client",
                "PROCESS", clt->label);
        return;
    }
    gpdgc_process *srv = gpdgc_do_get_process(server->servers, address);
    if (srv != NULL)
    {
        g_info("%-10s: Ignore client candidate: '%s' is already a server",
                "PROCESS", srv->label);
        return;
    }
    gpdgc_process *old = gpdgc_do_get_process(server->previouses, address);
    if (old != NULL)
    {
        g_info("%-10s: Ignore client candidate: '%s' has been recently removed",
                "PROCESS", old->label);
        return;
    }

    char *label = gpdgc_get_address_label(address);
    gpdgc_client_candidate *candidate =
        gpdgc_get_client_candidate(server, address);
    if (candidate == NULL)
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Cannot process addition of '%s'" "PROCESS", label);
        gcry_sexp_release(key);
        free(label);
        return;
    }

    if (gpdgc_contains_address(candidate->voters, voter->address))
    {
        g_info("%-10s: '%s' has been already proposed by '%s'",
                "PROCESS", label, voter->label);
        free(label);
        return;
    }
    candidate->voters = g_slist_append(candidate->voters, voter->address);
    candidate->keys = g_slist_append(candidate->keys, key);

    g_debug("%-10s: '%s' has been proposed by '%s'",
            "PROCESS", label, voter->label);
    free(label);
}


/* Close client candidate */
void gpdgc_close_client_candidate(gpdgc_iserver *server, struct sockaddr *clt)
{
    gpdgc_client_candidate *candidate = gpdgc_get_client_candidate(server, clt);
    gpdgc_remove_client_candidate(server, candidate);
}


/* Signal view change to the server */
gpdgc_message *gpdgc_get_initial_view_message(gpdgc_iserver *server)
{
    gpdgc_process *local = server->local;
    gpdgc_message *msg = gpdgc_create_message();
    if (msg == NULL)
    {
        gpdgc_free_message(msg);
        return NULL;
    }

    GSList *reversed_clients = g_slist_reverse(g_slist_copy(server->clients));
    GSList *client_iterator = reversed_clients;
    while (client_iterator != NULL)
    {
        gpdgc_process *client = client_iterator->data;
        client_iterator = client_iterator->next;

        unsigned long sn = client->sequence_number;
        size_t address_size = gpdgc_get_address_size(client->address);
        if ((!gpdgc_push_content(msg, &sn, sizeof(unsigned long)))
                || (!gpdgc_push_gcry_sexp(msg, client->public_key))
                || (!gpdgc_push_content(msg, client->address, address_size)))
        {
            gpdgc_free_message(msg);
            return NULL;
        }
    }
    g_slist_free(reversed_clients);

    unsigned long key_id = server->trusted_key_identifier;
    unsigned long view_id = server->view_identifier;
    if ((!gpdgc_push_content(msg, &local->phase, sizeof(unsigned long)))
            || (!gpdgc_push_content(msg, &view_id, sizeof(unsigned long)))
            || (!gpdgc_push_content(msg, &key_id, sizeof(unsigned long)))
            || (!gpdgc_push_gcry_sexp(msg, server->trusted_key)))
    {
        gpdgc_free_message(msg);
        return NULL;
    }

    GSList *reversed_servers = g_slist_reverse(g_slist_copy(server->servers));
    GSList *server_iterator = reversed_servers;
    while (server_iterator != NULL)
    {
        gpdgc_process *server = server_iterator->data;
        server_iterator = server_iterator->next;

        unsigned long sn = server->sequence_number;
        size_t address_size = gpdgc_get_address_size(server->address);
        if ((!gpdgc_push_content(msg, &sn, sizeof(unsigned long)))
                || (!gpdgc_push_gcry_sexp(msg, server->public_key))
                || (!gpdgc_push_content(msg, server->address, address_size)))
        {
            gpdgc_free_message(msg);
            return NULL;
        }
    }
    g_slist_free(reversed_servers);

    unsigned short type = GPDGC_CANDIDATE_MESSAGE_TYPE;
    if (!gpdgc_push_content(msg, &type, sizeof(unsigned short)))
    {
        gpdgc_free_message(msg);
        return NULL;
    }
    return msg;
}
gpdgc_message *gpdgc_get_view_info_message(gpdgc_iserver *server)
{
    gpdgc_message *msg = gpdgc_create_message();
    if (msg == NULL)
    {
        return NULL;
    }

    GSList *reversed_servers = g_slist_reverse(g_slist_copy(server->servers));
    GSList *server_iterator = reversed_servers;
    while (server_iterator != NULL)
    {
        gpdgc_process *iterated = server_iterator->data;
        server_iterator = server_iterator->next;

        unsigned short suspiscions = iterated->suspiscion_flags; 
        size_t address_size = gpdgc_get_address_size(iterated->address);
        if ((!gpdgc_push_content(msg, &suspiscions, sizeof(unsigned short)))
                || (!gpdgc_push_gcry_sexp(msg, iterated->public_key))
                || (!gpdgc_push_content(msg, iterated->address, address_size)))
        {
            gpdgc_free_message(msg);
            return NULL;
        }
    }
    g_slist_free(reversed_servers);

    unsigned long key_id = server->trusted_key_identifier;
    unsigned long view_id = server->view_identifier;
    unsigned long sn = ++server->view_info_identifier;
    unsigned short type = GPDGC_INFORMATION_MESSAGE_TYPE;
    if ((!gpdgc_push_gcry_sexp(msg, server->trusted_key))
            || (!gpdgc_push_content(msg, &key_id, sizeof(unsigned long)))
            || (!gpdgc_push_content(msg, &view_id, sizeof(unsigned long)))
            || (!gpdgc_push_content(msg, &sn, sizeof(unsigned long)))
            || (!gpdgc_push_content(msg, &type, sizeof(unsigned short))))
    {
        gpdgc_free_message(msg);
        return NULL;
    }

    GSList *client_iterator = server->clients;
    while (client_iterator != NULL)
    {
        gpdgc_process *client = client_iterator->data;
        client_iterator = client_iterator->next;

        client->last_view_aware = 0; 
    }
    return msg;
}
int gpdgc_add_server(gpdgc_iserver *server, struct sockaddr *address, 
        gcry_sexp_t public_key, unsigned long sequence_number,
        unsigned long phase, short last_view_aware)
{
    g_assert(gpdgc_do_get_process(server->servers, address) == NULL);
    g_assert(gpdgc_do_get_process(server->clients, address) == NULL);
    g_assert(gpdgc_do_get_process(server->previouses, address) == NULL);
    g_assert((public_key != NULL) || (!gpdgc_has_certified_servers(server)));

    gpdgc_process *old = gpdgc_do_get_process(server->previouses, address);
    if (old != NULL)
    {
        g_error("%-10s: server '%s' cannot be added: it was recently removed",
                "PROCESS", old->label);
    }

    gpdgc_process *result = NULL;
    if (gpdgc_cmp_address(server->local->address, address) == 0)
    {
        result = server->local;
        result->public_key = public_key;
        result->sequence_number = sequence_number;
        free(address);
    }
    else
    {
        result = gpdgc_create_process(address, GPDGC_SERVER, 
                public_key, sequence_number);
    }
    if (result == NULL)
    {
        char *label = gpdgc_get_address_label(address);
        gpdgc_signal_lack_of_memory(server,
                "%-10s: process '%s' cannot be added", "PROCESS", label);
        free(label);
        free(address);
        gcry_sexp_release(public_key);
        return 0;
    }
    result->phase = phase;
    result->last_view_aware = last_view_aware;
    result->excluded_from_view = server->view_identifier;
    result->removal_phase = phase;

    /* Update containers not already delivered with the new server */
    GSList *processes = g_slist_copy(server->servers);
    processes = g_slist_concat(processes, g_slist_copy(server->clients));
    GSList *iterator = processes;
    while (iterator != NULL)
    {
        gpdgc_process *iterated = iterator->data;
        iterator = iterator->next;

        GSList *container_iterator = iterated->undelivered_containers;
        while (container_iterator != NULL)
        {
            gpdgc_container *container = container_iterator->data;
            container_iterator = container_iterator->next;

            if (!gpdgc_add_container_state(container, result))
            {
                gpdgc_signal_lack_of_memory(server,
                        "%-10s: containers for process '%s' cannot be created",
                        "PROCESS", result->label);
                gpdgc_free_process(result);
                return 0;
            }
        }
    }
    g_slist_free(processes);

    /* Add the server */
    server->servers = g_slist_append(server->servers, result);
    return 1;
}
int gpdgc_add_client(gpdgc_iserver *server, struct sockaddr *address,
        gcry_sexp_t public_key, unsigned long sequence_number)
{
    g_assert(gpdgc_do_get_process(server->clients, address) == NULL);
    g_assert(gpdgc_do_get_process(server->servers, address) == NULL);
    g_assert(gpdgc_do_get_process(server->previouses, address) == NULL);

    gpdgc_process *old = gpdgc_do_get_process(server->previouses, address);
    if (old != NULL)
    {
        g_error("%-10s: client '%s' cannot be added: it was recently removed",
                "PROCESS", old->label);
    }

    gpdgc_process *client = gpdgc_create_process(address, GPDGC_CLIENT,
            public_key, sequence_number);
    if (client == NULL)
    {
        char *label = gpdgc_get_address_label(address);
        gpdgc_signal_lack_of_memory(server,
                "%-10s: client '%s' cannot be added", "PROCESS", label);
        free(label);
        free(address);
        return 0;
    }
    server->clients = g_slist_append(server->clients, client);
    return 1;
}
int gpdgc_is_client_candidate_acceptable(gpdgc_iserver *server,
        gpdgc_client_candidate *candidate, gcry_sexp_t *key)
{
    unsigned int max_byzantine = gpdgc_get_max_byzantine(server);

    GSList *key_iterator = candidate->keys;
    while (key_iterator != NULL)
    {
        gcry_sexp_t iterated = key_iterator->data;
        key_iterator = key_iterator->next;

        unsigned int nb_voters = 1;
        GSList *tmp_iterator = key_iterator;
        while ((tmp_iterator != NULL) && (nb_voters <= max_byzantine))
        {
            gcry_sexp_t tmp = tmp_iterator->data;
            tmp_iterator = tmp_iterator->next;

            GError *cmp_exception = NULL;
            int cmp = gpdgc_cmp_gcry_sexp_t(tmp, iterated, &cmp_exception);
            if (cmp_exception != NULL)
            {
                gpdgc_signal_lack_of_memory(server,
                        "%-10s: Cannot count similar keys", "PROCESS");
                return 0;
            }
            nb_voters += (cmp == 0 ? 1 : 0);
        }

        if (nb_voters > max_byzantine)
        {
            *key = iterated;
            return 1;
        }
    }
    return 0;
}
void gpdgc_clean_container_from(gpdgc_container *container,
        struct sockaddr *address)
{
    GSList *state_iterator = container->states;
    while (state_iterator != NULL)
    {
        gpdgc_container_state *state = state_iterator->data;
        state_iterator = state_iterator->next;

        if (gpdgc_cmp_address(state->owner->address, address) == 0)
        {
            container->states = g_slist_remove(container->states, state);
            gpdgc_free_container_state(state);
        }
    }
}
void gpdgc_clean_containers_from(GSList *processes,
        gpdgc_process *process, int process_delivered_containers)
{
    GSList *process_iterator = processes;
    while (process_iterator != NULL)
    {
        gpdgc_process *iterated = (gpdgc_process *) process_iterator->data;
        process_iterator = process_iterator->next;

        GSList *container_iterator = process_delivered_containers
            ? iterated->delivered_containers : iterated->undelivered_containers;
        while (container_iterator != NULL)
        {
            void *container = container_iterator->data;
            container_iterator = container_iterator->next;

            gpdgc_clean_container_from(container, process->address);
        }
    }
}
void gpdgc_clean_process(gpdgc_iserver *server, gpdgc_process *proc)
{
    g_slist_free_full(proc->undelivered_containers, gpdgc_free_container);
    proc->undelivered_containers = NULL;
    g_slist_free_full(proc->replies, gpdgc_free_reply);
    proc->replies = NULL;
    g_slist_free_full(proc->futures, gpdgc_free_future);
    proc->futures = NULL;
    if (proc->current != NULL)
    {
        gpdgc_free_round(proc->current);
        proc->current = NULL;
    }
    proc->last_view_aware = 0;
    proc->state = GPDGC_INACTIVE;
    proc->removal_phase = server->next_phase - 1;

    server->previouses = g_slist_append(server->previouses, proc);
}
void gpdgc_remove_server(gpdgc_iserver *server, struct sockaddr *address)
{
    GSList *process_iterator = server->servers;
    while (process_iterator != NULL)
    {
        gpdgc_process *iterated = process_iterator->data;
        process_iterator = process_iterator->next;

        if (gpdgc_cmp_address(address, iterated->address) == 0)
        {
            server->servers = g_slist_remove(server->servers, iterated);
            gpdgc_clean_containers_from(server->clients, iterated, 0);
            gpdgc_clean_containers_from(server->servers, iterated, 0);
            gpdgc_clean_containers_from(server->previouses, iterated, 0);
            gpdgc_clean_process(server, iterated);
            return;
        }
    }
}
int gpdgc_remove_client(gpdgc_iserver *server, struct sockaddr *address)
{
    GSList *client_iterator = server->clients;
    while (client_iterator != NULL)
    {
        gpdgc_process *client = client_iterator->data;
        client_iterator = client_iterator->next;

        if (gpdgc_cmp_address(address, client->address) == 0)
        {
            server->clients = g_slist_remove(server->clients, client);
            gpdgc_clean_process(server, client);
            return 1;
        }
    }
    return 0;
}
void gpdgc_apply_pending_view_changes(gpdgc_iserver *server)
{
    int server_has_changed = 0;
    unsigned int nb_added_servers = g_slist_length(server->server_candidates);
    unsigned int nb_added_keys = g_slist_length(server->server_candidate_keys);
    if (nb_added_servers != nb_added_keys)
    {
        g_error("%-10s: Invalid internal message: the number of added "
                "servers (%d) and added keys (%d) are not coherent",
                "PROCESS", nb_added_servers, nb_added_keys);
        return;
    }

    free(server->init_view_cache);
    server->init_view_cache = NULL;

    /* Remove the local process if required */  
    gpdgc_process *local = server->local;
    if (gpdgc_contains_address(server->server_exclusions, local->address))
    {
        gpdgc_signal_event(server, GPDGC_VIEW_EXCLUSION);
        gpdgc_internally_close_server(server);
        return;
    }

    /* Remove servers */
    GSList *removed_iterator = server->server_exclusions;
    while (removed_iterator != NULL)
    {
        struct sockaddr *removed = removed_iterator->data;
        removed_iterator = removed_iterator->next;

        char *label = gpdgc_get_address_label(removed);
        g_debug("%-10s: Remove server '%s'", "PROCESS", label);
        gpdgc_remove_server(server, removed);
        server_has_changed = 1;
        free(label);
    }

    /* Remove clients */
    removed_iterator = server->client_exclusions;
    while (removed_iterator != NULL)
    {
        struct sockaddr *removed = removed_iterator->data;
        removed_iterator = removed_iterator->next;

        char *label = gpdgc_get_address_label(removed);
        g_debug("%-10s: Unsubscribe client '%s'", "PROCESS", label);
        gpdgc_remove_client(server, removed);
        free(label);
    }

    /* Add servers */
    unsigned int nb_servers = g_slist_length(server->servers);
    GSList *added_iterator = server->server_candidates;
    GSList *key_iterator = server->server_candidate_keys;
    while ((added_iterator != NULL) && (key_iterator != NULL))
    {
        struct sockaddr *added = added_iterator->data;
        added_iterator = added_iterator->next;

        gcry_sexp_t public_key = key_iterator->data;
        key_iterator = key_iterator->next;

        gpdgc_process *client = gpdgc_do_get_process(server->clients, added);
        gpdgc_process *srv = gpdgc_do_get_process(server->servers, added);
        gpdgc_process *old = gpdgc_do_get_process(server->previouses, added);
        if (srv != NULL)
        {
            g_info("%-10s: Cannot add process '%s' to the current view: "
                    "process is already a server", "PROCESS", srv->label);
            free(added);
            gcry_sexp_release(public_key);
        }
        else if (client != NULL)
        {
            g_info("%-10s: Cannot add process '%s' to the current view: "
                    "process is already a client", "PROCESS", client->label);
            free(added);
            gcry_sexp_release(public_key);
        }
        else if (old != NULL)
        {
            g_info("%-10s: Cannot add process '%s' to the current view: "
                    "process has been recently removed", "PROCESS", old->label);
            free(added);
            gcry_sexp_release(public_key);
        }
        else if (nb_servers >= server->max_servers)
        {
            char *label = gpdgc_get_address_label(added);
            g_info("%-10s: Cannot add process '%s' to the current view: "
                    "limit of servers has been reached", "PROCESS", label);
            free(label);
            free(added);
            gcry_sexp_release(public_key);
        }
        else if (!gpdgc_add_server(server, added, public_key,
                    GPDGC_DEFAULT_INITIAL_SEQUENCE_NUMBER, local->phase, 0))
        {
            char *label = gpdgc_get_address_label(added);
            g_critical("%-10s: Cannot add process '%s' to the current view: "
                    "an error occured while addition", "PROCESS", label);
            free(label);

            gpdgc_internally_close_server(server);
            return;
        }
        else 
        {
            char *label = gpdgc_get_address_label(added);
            g_debug("%-10s: Add server '%s'", "PROCESS", label);
            free(label);

            server_has_changed = 1;
            nb_servers++;
        }
    }

    /* Add acceptable clients */
    unsigned int nb_clients = g_slist_length(server->clients);
    GSList *candidate_iterator = server->client_candidates;
    while ((candidate_iterator != NULL) && (nb_clients < server->max_clients))
    {
        gpdgc_client_candidate *candidate = candidate_iterator->data;
        candidate_iterator = candidate_iterator->next;

        gcry_sexp_t ref_key = NULL;
        if (gpdgc_is_client_candidate_acceptable(server, candidate, &ref_key))
        {
            char *label = gpdgc_get_address_label(candidate->client);
            g_debug("%-10s: Accept client '%s'", "PROCESS", label);
            free(label);

            gpdgc_add_client(server, candidate->client, ref_key,
                    GPDGC_DEFAULT_INITIAL_SEQUENCE_NUMBER);
            nb_clients++;

            candidate->client = NULL;
            candidate->keys = g_slist_remove(candidate->keys, ref_key);
            gpdgc_remove_client_candidate(server, candidate);
        }
    }

    /* Process the remainder clients */
    candidate_iterator = server->client_candidates;
    while (candidate_iterator != NULL)
    {
        gpdgc_client_candidate *candidate = candidate_iterator->data;
        candidate_iterator = candidate_iterator->next;

        if ((nb_clients >= server->max_clients) && (candidate->status != 3))
        {
            /* Reject the candidate */
            candidate->status = 3;
            gpdgc_send_candidate_feedback(server,
                    candidate, GPDGC_NACK_SUBSCRIPTION_MESSAGE_TYPE);
        }
        else if ((nb_clients < server->max_clients) && (server_has_changed))
        {
            /* Restart the acceptance procedure upon view change */
            candidate->status = candidate->status == 0 ? 0 : 1;

            g_slist_free(candidate->voters);
            candidate->voters = NULL;
            
            g_slist_free_full(candidate->keys,
                    (void (*)(void *))gcry_sexp_release);
            candidate->keys = NULL;

            free(candidate->feedback);
            candidate->feedback = NULL;

            pthread_cond_broadcast(&server->client_condition);
        }
    }

    if (server_has_changed)
    {
        server->view_identifier++;
        g_debug("%-10s: View '%lu' (%d servers) has been installed !",
                "PROCESS", server->view_identifier,
                g_slist_length(server->servers));
        gpdgc_signal_event(server, GPDGC_VIEW_UPDATE);

        /* Reset ignore message */
        GSList *server_iterator = server->servers;
        while (server_iterator != NULL)
        {
            gpdgc_process *iterated = server_iterator->data;
            server_iterator = server_iterator->next;

            iterated->excluded_from_view = server->view_identifier;
        }

        /* Send init message to added servers */
        gcry_sexp_t key = gpdgc_get_channel_key(server);
        gpdgc_message *init_message = gpdgc_get_initial_view_message(server);
        if (init_message == NULL)
        {
            gpdgc_signal_lack_of_memory(server,
                    "%-10s: Cannot build initialisation message", "PROCESS");
            return;
        }
        free(server->init_view_cache);
        server->init_view_cache = gpdgc_write_contents(init_message, key,
                &server->init_view_cache_size);
        server->init_view_remaining_ticks = server->resend_period;
        gpdgc_free_message(init_message);

        if (server->init_view_cache == NULL)
        {
            gpdgc_signal_lack_of_memory(server,
                    "%-10s: Cannot buffer initialisation message", "PROCESS");
        }
        gpdgc_udp_multicast(server->socket, server->init_view_cache,
                server->init_view_cache_size, server->server_candidates);
    }

    /* Send last view info message to clients */
    gpdgc_udp_client_multicast(server,
            server->view_info_cache, server->view_info_cache_size);
}


/* Set the initial view */
int gpdgc_set_initial_view(gpdgc_iserver *server,
        GSList *servers, GSList *server_pks, GSList *server_sns,
        GSList *clients, GSList *client_pks, GSList *client_sns,
        unsigned long phase, unsigned long view_id)
{
    g_assert(server->servers == NULL);
    g_assert(server->clients == NULL);
    g_assert(server->previouses == NULL);

    if (g_slist_length(servers) > server->max_servers)
    {
        g_error("%-10s: Initial view cannot be set: "
                "init view contains %d servers (limit is '%d')",
                "PROCESS", g_slist_length(servers), server->max_servers);
    }
    if (g_slist_length(clients) > server->max_clients)
    {
        g_error("%-10s: Initial view cannot be set: "
                "init view considers %d clients (limit is '%d')",
                "PROCESS", g_slist_length(clients), server->max_clients);
    }

    int result = 1;
    server->local->sequence_number = 0;
    server->next_sequence_number = 0;
    server->next_phase = phase;
    server->view_identifier = view_id;

    GSList *addr_iterator = servers;
    GSList *pk_iterator = server_pks;
    GSList *sn_iterator = server_sns;
    while (addr_iterator != NULL)
    {
        struct sockaddr *addr = addr_iterator->data;
        addr_iterator = addr_iterator->next;

        gcry_sexp_t pk = pk_iterator != NULL ? pk_iterator->data : NULL;
        pk_iterator = pk_iterator != NULL ? pk_iterator->next : NULL; 

        unsigned long sn = sn_iterator != NULL
            ? *((unsigned long *) sn_iterator->data)
            : GPDGC_DEFAULT_INITIAL_SEQUENCE_NUMBER;
        sn_iterator = sn_iterator != NULL ? sn_iterator->next : NULL; 

        char *label = gpdgc_get_address_label(addr);
        if (gpdgc_do_get_process(server->servers, addr) != NULL)
        {
            g_info("%-10s: Server '%s' has been specified more than once "
                    "in the initial view.", "PROCESS", label);
            free(addr);
            gcry_sexp_release(pk);
        }
        else if (gpdgc_has_certified_servers(server) && (pk == NULL))
        {
            g_error("%-10s: Server '%s' cannot be added: "
                    "a public key is required", "PROCESS", label);
            free(addr);
            gcry_sexp_release(pk);
            result = 0;
        }
        else
        {
            result = result & gpdgc_add_server(server, addr, pk, sn, phase, 1);
        }
        free(label);
    }

    addr_iterator = clients;
    pk_iterator = client_pks;
    sn_iterator = client_sns;
    while (addr_iterator != NULL)
    {
        struct sockaddr *addr = addr_iterator->data;
        addr_iterator = addr_iterator->next;

        gcry_sexp_t pk = pk_iterator != NULL ? pk_iterator->data : NULL;
        pk_iterator = pk_iterator != NULL ? pk_iterator->next : NULL; 

        unsigned long sn = sn_iterator != NULL
            ? *((unsigned long *) sn_iterator->data)
            : GPDGC_DEFAULT_INITIAL_SEQUENCE_NUMBER;
        sn_iterator = sn_iterator != NULL ? sn_iterator->next : NULL; 

        gpdgc_process *clt = gpdgc_do_get_process(server->clients, addr);
        gpdgc_process *srv = gpdgc_do_get_process(server->servers, addr);
        if (srv != NULL)
        {
            g_info("%-10s: Client '%s' has already been specified as a server",
                    "PROCESS", srv->label);
            free(addr);
            gcry_sexp_release(pk);
            result = 0;
        }
        else if (clt != NULL)
        {
            g_info("%-10s: Client '%s' has been specified more than once "
                    "in the initial view", "PROCESS", clt->label);
            free(addr);
            gcry_sexp_release(pk);
        }
        else
        {
            result = result & gpdgc_add_client(server, addr, pk, sn);
        }
    }

    if (result)
    {
        g_debug("%-10s: Initial view '%lu' (%d servers) has been set !",
                "PROCESS", server->view_identifier,
                g_slist_length(server->servers));
        g_slist_free_full(server->expected_view, free);
        server->expected_view = NULL;
        g_slist_free_full(server->view_candidates, gpdgc_free_view_candidate);
        server->view_candidates = NULL;

        gpdgc_signal_event(server, GPDGC_VIEW_INIT);
        gpdgc_signal_state_change(server, GPDGC_READY);
    }
    else
    {
        g_critical("%-10s: Installation of the initial view failed", "PROCESS");
        server->servers = g_slist_remove(server->servers, server->local);
        g_slist_free_full(server->servers, gpdgc_free_process);
        server->servers = NULL;
        g_slist_free_full(server->clients, gpdgc_free_process);
        server->clients = NULL;
    }
    return result;
}


/* Set expected view */
short gpdgc_is_expected_view(gpdgc_iserver *server,
        gpdgc_view_candidate *candidate)
{
    if (g_slist_length(candidate->servers) > server->max_servers)
    {
        return 0;
    }
    if (g_slist_length(candidate->clients) > server->max_clients)
    {
        return 0;
    }

    unsigned int counter = 0;
    GSList *iterator = server->expected_view;;
    while (iterator != NULL)
    {
        struct sockaddr *address = iterator->data;
        iterator = iterator->next;

        counter += (gpdgc_contains_address(candidate->servers, address) ? 1: 0);
    }
    return counter > g_slist_length(server->expected_view) / 2;
}
void gpdgc_set_expected_view(gpdgc_iserver *server, GSList *view)
{
    server->expected_view = g_slist_copy(view);
    gpdgc_signal_state_change(server, GPDGC_WAITING);

    int is_byzantine = gpdgc_is_byzantine_model(server);
    unsigned short expected_view_size = g_slist_length(server->expected_view);
    unsigned short threshold = is_byzantine ? expected_view_size / 3 : 0;

    GSList *iterator = server->view_candidates;
    while (iterator != NULL)
    {
        gpdgc_view_candidate *candidate = iterator->data;
        iterator = iterator->next;

        if (!gpdgc_is_expected_view(server, candidate))
        {
            server->view_candidates =
                g_slist_remove(server->view_candidates, candidate);
            gpdgc_free_view_candidate(candidate);
        }
        else if (g_slist_length(candidate->voters) > threshold)
        {
            server->view_candidates =
                g_slist_remove(server->view_candidates, candidate);
            if ((!gpdgc_set_initial_view(server,
                            candidate->servers, candidate->server_keys,
                            candidate->server_seq_numbers,
                            candidate->clients, candidate->client_keys,
                            candidate->client_seq_numbers,
                            candidate->phase, candidate->view_identifier))
                    || (!gpdgc_set_trusted_key(server, candidate->trusted_key,
                            candidate->trusted_key_identifier)))
            {
                gpdgc_free_view_candidate(candidate);
                return;
            }

            g_slist_free(candidate->servers);
            g_slist_free(candidate->server_keys);
            g_slist_free_full(candidate->server_seq_numbers, free);
            g_slist_free(candidate->clients);
            g_slist_free(candidate->client_keys);
            g_slist_free_full(candidate->client_seq_numbers, free);
            free(candidate);
            return;
        }
    }
}


/* Deliver candidate view */
gpdgc_view_candidate *gpdgc_extract_view_candidate(gpdgc_message *message)
{
    gpdgc_view_candidate *result = gpdgc_create_view_candidate();
    if (result == NULL)
    {
        return NULL;
    }

    size_t current_content_size;
    void *current_content = gpdgc_pop_content(message, &current_content_size);
    while (gpdgc_is_address(current_content, current_content_size))
    {
        struct sockaddr *address = current_content;
        result->servers = g_slist_append(result->servers, address);

        size_t buffer_size;
        void *buffer = gpdgc_pop_content(message, &buffer_size);
        gcry_sexp_t key = NULL;
        if ((buffer_size > 0) && gcry_sexp_new(&key, buffer, buffer_size, 0))
        {
            g_warning("%-10s: Invalid view: unreadable public key", "PROCESS");
            gpdgc_free_view_candidate(result);
            free(buffer);
            return NULL;
        }
        result->server_keys = g_slist_append(result->server_keys, key);
        free(buffer);

        size_t sn_size;
        unsigned long *sn = gpdgc_pop_content(message, &sn_size);
        if (sn_size != sizeof(unsigned long))
        {
            g_warning("%-10s: Invalid view: unreadable seq number", "PROCESS");
            gpdgc_free_view_candidate(result);
            free(sn);
            return NULL;
        }
        result->server_seq_numbers =
            g_slist_append(result->server_seq_numbers, sn);

        current_content = gpdgc_pop_content(message, &current_content_size);
    }

    gcry_sexp_t trusted_key = NULL;
    if ((current_content_size > 0)
            && gcry_sexp_new(&trusted_key, current_content,
                current_content_size, 0))
    {
        g_warning("%-10s: Invalid view: unreadable trusted key", "PROCESS");
        gpdgc_free_view_candidate(result);
        free(current_content); 
        return NULL;
    }
    free(current_content);
    result->trusted_key = trusted_key;

    size_t key_id_size;
    unsigned long *key_id = gpdgc_pop_content(message, &key_id_size);
    if (key_id_size != sizeof(unsigned long))
    {
        g_warning("%-10s: Invalid view: unreadable key identifier", "PROCESS");
        gpdgc_free_view_candidate(result);
        return NULL;
    }
    result->trusted_key_identifier = *key_id;
    free(key_id);

    size_t view_id_size;
    unsigned long *view_id = gpdgc_pop_content(message, &view_id_size);
    if (view_id_size != sizeof(unsigned long))
    {
        g_warning("%-10s: Invalid view: unreadable view identifier", "PROCESS");
        gpdgc_free_view_candidate(result);
        return NULL;
    }
    result->view_identifier = *view_id;
    free(view_id);

    size_t phase_size;
    unsigned long *phase = gpdgc_pop_content(message, &phase_size);
    if (phase_size != sizeof(unsigned long))
    {
        g_warning("%-10s: Invalid view: unreadable initial phase", "PROCESS");
        gpdgc_free_view_candidate(result);
        return NULL;
    }
    result->phase = *phase;
    free(phase);

    current_content = gpdgc_pop_content(message, &current_content_size);
    while (gpdgc_is_address(current_content, current_content_size))
    {
        struct sockaddr *address = current_content;
        result->clients = g_slist_append(result->clients, address);

        size_t buffer_size;
        void *buffer = gpdgc_pop_content(message, &buffer_size);
        gcry_sexp_t key = NULL;
        if ((buffer_size > 0) && gcry_sexp_new(&key, buffer, buffer_size, 0))
        {
            g_warning("%-10s: Invalid view: unreadable public key", "PROCESS");
            gpdgc_free_view_candidate(result);
            free(buffer);
            return NULL;
        }
        result->client_keys = g_slist_append(result->client_keys, key);
        free(buffer);

        size_t sn_size;
        unsigned long *sn = gpdgc_pop_content(message, &sn_size);
        if (sn_size != sizeof(unsigned long))
        {
            g_warning("%-10s: Invalid view: unreadable seq number", "PROCESS");
            gpdgc_free_view_candidate(result);
            free(sn);
            return NULL;
        }
        result->client_seq_numbers =
            g_slist_append(result->client_seq_numbers, sn);

        current_content = gpdgc_pop_content(message, &current_content_size);
    }
    return result;
}
void gpdgc_deliver_view_candidate(gpdgc_iserver *server, 
        gpdgc_message *message, struct sockaddr *sender)
{
    gpdgc_view_candidate *candidate = gpdgc_extract_view_candidate(message);
    gpdgc_free_message(message);
    if (candidate != NULL)
    {
        if (!gpdgc_contains_address(candidate->servers, sender))
        {
            g_warning("%-10s: Candidate does not contains sender", "PROCESS");
            gpdgc_free_view_candidate(candidate);
            return;
        }
        if (!gpdgc_contains_address(candidate->servers, server->local->address))
        {
            g_warning("%-10s: Candidate does not include local", "PROCESS");
            gpdgc_free_view_candidate(candidate);
            return;
        }

        short expect = server->expected_view != NULL;
        gpdgc_view_candidate *reference = NULL;
        GSList *candidate_iterator = server->view_candidates;
        while ((candidate_iterator != NULL) && (reference == NULL))
        {
            gpdgc_view_candidate *iterated = candidate_iterator->data;
            candidate_iterator = candidate_iterator->next;

            GError *exception = NULL;
            int cmp = gpdgc_cmp_view_candidate(candidate, iterated, &exception);
            if (exception != NULL)
            {
                gpdgc_signal_lack_of_memory(server,
                        "%-10s: Cannot count the view candidate", "PROCESS");
                gpdgc_free_view_candidate(candidate);
                return;
            }
            else if (cmp == 0)
            {
                reference = iterated;
                gpdgc_free_view_candidate(candidate);
            }
        }
        if (reference == NULL)
        {
            short valid = gpdgc_is_expected_view(server, candidate);
            if (expect && (!valid))
            {
                char *label = gpdgc_get_address_label(sender);
                g_info("%-10s: Receive an invalid view candidate from '%s'",
                        "PROCESS", label);
                gpdgc_free_view_candidate(candidate);
                free(label);
                return;
            }

            unsigned int nb_cands = g_slist_length(server->view_candidates); 
            if ((!expect) && (nb_cands >= server->max_servers))
            {
                char *label = gpdgc_get_address_label(sender);
                g_info("%-10s: Ignore candidate from '%s': already received "
                        "the maximum number of candidates", "PROCESS", label);
                gpdgc_free_view_candidate(candidate);
                free(label);
                return;
            }

            server->view_candidates =
                g_slist_append(server->view_candidates, candidate);
            reference = candidate;
        }

        if (gpdgc_contains_address(reference->voters, sender))
        {
            char *label = gpdgc_get_address_label(sender);
            g_info("%-10s: Already receive a view candidate from '%s'",
                    "PROCESS", label);
            free(label);
            return;
        }
        struct sockaddr *clone = gpdgc_clone_address(sender);
        if (clone == NULL)
        {
            gpdgc_signal_lack_of_memory(server,
                    "%-10s: Cannot clone view candidate's sender", "PROCESS");
            gpdgc_free_view_candidate(candidate);
            return;
        }
        reference->voters = g_slist_append(reference->voters, clone);

        int is_byzantine = gpdgc_is_byzantine_model(server);
        unsigned short expected_view_size = g_slist_length(server->expected_view);
        unsigned short threshold = is_byzantine ? expected_view_size / 3 : 0;
        unsigned short nb_votes = g_slist_length(reference->voters);
        if (expect && (nb_votes > threshold))
        {
            server->view_candidates =
                g_slist_remove(server->view_candidates, reference);
            if ((!gpdgc_set_initial_view(server,
                            reference->servers, reference->server_keys,
                            reference->server_seq_numbers,
                            reference->clients, reference->client_keys,
                            reference->client_seq_numbers,
                            reference->phase, reference->view_identifier))
                    || (!gpdgc_set_trusted_key(server, reference->trusted_key,
                            reference->trusted_key_identifier)))
            {
                gpdgc_free_view_candidate(reference);
                return;
            }

            g_slist_free(reference->servers);
            g_slist_free(reference->server_keys);
            g_slist_free_full(reference->server_seq_numbers, free);
            g_slist_free(reference->clients);
            g_slist_free(reference->client_keys);
            g_slist_free_full(reference->client_seq_numbers, free);
            g_slist_free_full(reference->voters, free);
            free(reference);
        }
        else
        {
            char *label = gpdgc_get_address_label(sender);
            g_debug("%-10s: Receive a view candidate from '%s', but "
                    "(1) threshold is not yet reached (%u < %u), or "
                    "(2) expected view is not defined",
                    "PROCESS", label, nb_votes, threshold);
            free(label);
        }
    }
}


/* Deliver the phase before which cache can be clean according to a server */
void gpdgc_deliver_clean_cache(gpdgc_iserver *server,
        unsigned long phase, gpdgc_process *origin)
{
    origin->removal_phase = phase;

    unsigned int max_byzantine = gpdgc_get_max_byzantine(server);
    GSList *iterator = server->previouses;
    while (iterator != NULL)
    {
        gpdgc_process *old = iterator->data;
        iterator = iterator->next;

        unsigned int counter = max_byzantine + 1;
        GSList *server_iterator = server->servers;
        while ((server_iterator != NULL) && (counter > 0))
        {
            gpdgc_process *iterated = server_iterator->data;
            server_iterator = server_iterator->next;

            if (gpdgc_cmp_counter(iterated->removal_phase,
                        old->removal_phase) > 0)
            {
                counter --;
            }
        }

        if (counter == 0)
        {
            g_debug("%-10s: Remove '%s' from memory", "PROCESS", old->label);
            if (old->type == GPDGC_SERVER)
            {
                gpdgc_clean_containers_from(server->clients, old, 1);
                gpdgc_clean_containers_from(server->servers, old, 1);
                gpdgc_clean_containers_from(server->previouses, old, 1);
            }
            server->previouses = g_slist_remove(server->previouses, old);
            gpdgc_free_process(old);
        }
    }
}


/* Send ignore message */
int gpdgc_send_excluded_message(gpdgc_iserver *server, struct sockaddr *address)
{
    unsigned short type = GPDGC_EXCLUDED_MESSAGE_TYPE;
    unsigned long view_id = server->view_identifier;
    gpdgc_message *msg = gpdgc_create_message();
    if ((msg == NULL)
            || (!gpdgc_push_content(msg, &view_id, sizeof(unsigned long)))
            || (!gpdgc_push_content(msg, &type, sizeof(unsigned short))))
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Unable to build ignore message", "SERVER");
        gpdgc_free_message(msg);
        return 0;
    }

    gcry_sexp_t key = gpdgc_get_channel_key(server);
    size_t size = 0;
    void *buffer = gpdgc_write_contents(msg, key, &size);
    gpdgc_free_message(msg);
    if (buffer == NULL)
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Unable to build client reply buffer", "BROADCAST");
        return 0;
    }

    char *label = gpdgc_get_address_label(address);
    g_debug("%-10s: Send excluded message to '%s'", "BROADCAST", label);
    free(label);

    int result = gpdgc_udp_send(server->socket, buffer, size, address);
    free(buffer);
    return result;
}


/* Deliver ignore message */
void gpdgc_deliver_excluded_message(gpdgc_iserver *server,
        unsigned long view_id, gpdgc_process *sender)
{
    if (gpdgc_cmp_counter(view_id, server->view_identifier) > 0)
    {
        sender->excluded_from_view = view_id;

        unsigned short threshold = gpdgc_get_max_byzantine(server) + 1;
        GSList *server_iterator = server->servers;
        while ((server_iterator != NULL) && (threshold > 0))
        {
            gpdgc_process *iterated = server_iterator->data;
            server_iterator = server_iterator->next;

            if (gpdgc_cmp_counter(iterated->excluded_from_view,
                        server->view_identifier) > 0)
            {
                threshold--;
            }
        }

        if (threshold == 0)
        {
            gpdgc_signal_event(server, GPDGC_VIEW_EXCLUSION);
            gpdgc_internally_close_server(server);
        }
    }
}
