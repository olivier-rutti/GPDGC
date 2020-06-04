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

#include "broadcast.h"
#include "consensus.h"
#include "heardof.h"
#include "process.h"

/* Free the memory occupied by a timed vote */ 
void gpdgc_free_timed_vote(void *void_vote)
{
    gpdgc_timed_vote *vote = void_vote;

    free(vote->vote);
    free(vote);
}


/* Get the max length of consensus message */
size_t gpdgc_get_proposition_length(gpdgc_validation_type validation)
{
    if (validation == GPDGC_AMNESIC_VALIDATION)
    {
        return 2;
    }
    if (validation == GPDGC_FULL_VALIDATION)
    {
        return 3;
    }
    return 1;
}


/* Get the size of a proposition */
size_t gpdgc_get_proposition_size(unsigned int nb_servers,
        unsigned int nb_clients, gpdgc_validation_type validation)
{
    size_t item_cost = gpdgc_get_message_item_cost();
    size_t msg_cost = gpdgc_get_message_cost();
    size_t vote_cost = (nb_clients + nb_servers) * sizeof(unsigned long);

    size_t result = msg_cost + item_cost + vote_cost;
    if ((validation == GPDGC_AMNESIC_VALIDATION)
            || (validation == GPDGC_FULL_VALIDATION))
    {
        result += item_cost + sizeof(unsigned long);
        if (validation == GPDGC_FULL_VALIDATION)
        {
            result += item_cost + 20 * nb_servers
                * (sizeof(GSList) + sizeof(gpdgc_timed_vote) + vote_cost);
        }
    }
    return result;
}


/* Get a consensus vote as a string */ 
char *gpdgc_get_vote_label(void *proposal, size_t size)
{
    int nb_values = size / sizeof(unsigned long);
    if ((proposal == NULL) || (nb_values == 0))
    {
        char *result = calloc(5, sizeof(char));
        strcpy(result, "NULL");
        return result;
    }

    unsigned long *values = (unsigned long *) proposal;
    int long_as_char_array_size = 20 * sizeof(char) + 1;
    char *result = malloc(nb_values * long_as_char_array_size);
    for (int i= 0; i<nb_values; i++)
    {
        sprintf(result + (i * long_as_char_array_size),
                i == nb_values - 1 ? "%020lu" : "%020lu:", values[i]); 
    }
    return result;
}


/* Extract/Write history from/to a buffer */
GSList *gpdgc_extract_history(void *buffer, size_t size)
{
    /* Build the group communication message */
    GSList *result = NULL;

    /* Read the buffer */ 
    size_t read_size = 0;
    while ((read_size < size)
            && (size - read_size > sizeof(size_t) + sizeof(unsigned long)))
    {
        gpdgc_timed_vote *selection = malloc(sizeof(gpdgc_timed_vote));
        if (selection == NULL)
        {
            g_slist_free_full(result, gpdgc_free_timed_vote);
            return NULL;
        }
        selection->vote = NULL;

        /* Extract the state timestamp */
        memcpy(&selection->timestamp,
                ((char *) buffer) + read_size, sizeof(unsigned long));
        read_size += sizeof(unsigned long);

        /* Extract the size of the state vote */
        memcpy(&selection->size, ((char *) buffer) + read_size, sizeof(size_t));
        read_size += sizeof(size_t);
        if (selection->size > size)
        {
            gpdgc_free_timed_vote(selection);
            g_slist_free_full(result, gpdgc_free_timed_vote);
            return NULL;	  
        }

        /* Extract the state vote */
        selection->vote = malloc(selection->size);
        if ((selection->vote == NULL) || (read_size + selection->size > size))
        {
            gpdgc_free_timed_vote(selection);
            g_slist_free_full(result, gpdgc_free_timed_vote);
            return NULL;	  
        }
        memcpy(selection->vote, ((char *) buffer) + read_size, selection->size);
        read_size += selection->size;

        /* Add the content to the result message */
        result = g_slist_append(result, selection);
    }

    /* The amount of read data should be equal to the buffer size */
    if (size != read_size)
    {
        g_slist_free_full(result, gpdgc_free_timed_vote);
        return NULL;
    }
    return result;
}
void *gpdgc_write_history(GSList *history, size_t *size)
{
    char *buffer = NULL;
    *size = 0;
    GSList *iterator = history;
    while (iterator != NULL)
    {
        gpdgc_timed_vote *selection = iterator->data;
        iterator = iterator->next;

        /* Memory allocation */
        void *new_buffer = realloc(buffer, *size + sizeof(unsigned long)
                + sizeof(size_t) + selection->size);
        if (new_buffer == NULL)
        {
            free(buffer);
            return NULL;
        }
        buffer = new_buffer;

        /* Write the timestamp in the buffer */
        memcpy(buffer + *size, &selection->timestamp, sizeof(unsigned long));
        *size += sizeof(unsigned long);

        /* Write the size of content in the buffer */
        memcpy(buffer + *size, &selection->size, sizeof(size_t));
        *size += sizeof(size_t);

        /* Write the content itself in the buffer */
        memcpy(buffer + *size, selection->vote, selection->size);
        *size += selection->size;
    }
    return buffer;
}


/* Extract the values according to a specific criteria */
void *gpdgc_peek_value(gpdgc_message *message, int i, size_t *size)
{
    size_t ul_size = sizeof(unsigned long);
    int is_decision = (gpdgc_get_content_size(message, 1) == ul_size)
        && (gpdgc_get_content_size(message, 2) == ul_size)
        && (gpdgc_get_content_size(message, 3) == ul_size);

    // NB: decision message may contain signature and clock
    int index = is_decision ? i + 4 : i;

    return gpdgc_peek_content(message, index, size);
}
gpdgc_message *gpdgc_get_any_value(gpdgc_iserver *server,
        gpdgc_process *process, unsigned long phi)
{
    UNUSED(server);
    UNUSED(phi);

    if (process->current->decision != NULL)
    {
        return process->current->decision;
    }
    return process->current->message;
}
gpdgc_message *gpdgc_get_consistent_value(gpdgc_iserver *server,
        gpdgc_process *process, unsigned long phi)
{
    UNUSED(server);
    UNUSED(phi);

    if (process->current->flags & GPDGC_ROUND_MESSAGE_SAFE_FLAG)
    {
        return process->current->message;
    }
    return NULL;
}
gpdgc_message *gpdgc_get_honest_value(gpdgc_iserver *server,
        gpdgc_process *process, unsigned long phi)
{
    UNUSED(phi);

    gpdgc_message *result = process->current->message;
    if (result != NULL)
    {
        size_t size;
        void *value = gpdgc_peek_value(result, 0, &size); 

        size_t ts_size;
        unsigned long *ts = gpdgc_peek_content(result, 1, &ts_size);

        unsigned int counter = gpdgc_get_max_byzantine(server) + 1; 
        GSList *iterator =
            ts_size == sizeof(unsigned long) ? server->servers : NULL;
        while ((iterator != NULL) && (counter > 0))
        {
            gpdgc_process *iterated = iterator->data;
            iterator = iterator->next;

            gpdgc_message *other = iterated->current->decision;
            int consider_decision = other != NULL;
            if (!consider_decision)
            {
                other = iterated->current->message;
            }

            if (other != NULL)
            {
                size_t other_size;
                void *other_value = gpdgc_peek_value(other, 0, &other_size); 

                size_t other_ts_size;
                unsigned long *other_ts =
                    gpdgc_peek_content(other, 1, &other_ts_size);
                if ((other_ts_size == sizeof(unsigned long))
                        && (size == other_size) 
                        && (memcmp(value, other_value, size) == 0)
                        && (consider_decision || (*ts == *other_ts)))
                {
                    counter --;
                }
            }
        }

        if (counter > 0)
        {
            result = NULL;
        }
    }
    return result;
}
unsigned int gpdgc_get_validated_threshold(gpdgc_iserver *server)
{
    unsigned short mlt = 1;
    if (gpdgc_is_byzantine_model(server)
            && (server->validation == GPDGC_AMNESIC_VALIDATION))
    {
        mlt++;
    }
    return g_slist_length(server->servers) - mlt * gpdgc_get_max_faulty(server);
}
gpdgc_message *gpdgc_get_validated_value(gpdgc_iserver *server,
        gpdgc_process *process, unsigned long phi)
{
    UNUSED(phi);

    if (process->current->decision != NULL)
    {
        return process->current->decision;
    }

    gpdgc_message *result = process->current->message;
    if (result != NULL)
    {
        size_t size;
        void *value = gpdgc_peek_value(result, 0, &size); 
        
        size_t ts_size;
        unsigned long *ts = gpdgc_peek_content(result, 1, &ts_size);

        unsigned int counter = gpdgc_get_validated_threshold(server);
        GSList *iterator =
            (ts_size == sizeof(unsigned long)) ? server->servers : NULL;
        while ((iterator != NULL) && (counter > 0))
        {
            gpdgc_process *iterated = iterator->data;
            iterator = iterator->next;

            gpdgc_message *other = iterated->current->decision;
            int consider_decision = other != NULL;
            if (!consider_decision)
            {
                other = iterated->current->message;
            }

            if (other != NULL)
            {
                size_t other_size;
                void *other_value = gpdgc_peek_value(other, 0, &other_size); 

                size_t other_ts_size;
                unsigned long *other_ts =
                    gpdgc_peek_content(other, 1, &other_ts_size);
                if (((size == other_size) 
                            && (memcmp(value, other_value, size) == 0))
                        || ((!consider_decision)
                            && (other_ts_size == sizeof(unsigned long)) 
                            && (gpdgc_cmp_counter(*ts, *other_ts) > 0)))
                {
                    counter --;
                }
            }
        }

        if (counter > 0)
        {
            result = NULL;
        }
    }
    return result;
}
gpdgc_message *gpdgc_get_phased_value(gpdgc_iserver *server,
        gpdgc_process *process, unsigned long phi)
{
    UNUSED(server);

    if (process->current->decision != NULL)
    {
        return process->current->decision;
    }

    gpdgc_message *result = process->current->message;
    if (result != NULL)
    {
        size_t size;
        unsigned long *timestamp = gpdgc_peek_content(result, 1, &size);
        if ((size != sizeof(unsigned long)) || (*timestamp != phi))
        {
            result = NULL;
        }
    }
    return result; 
}
gpdgc_message *gpdgc_get_decision_value(gpdgc_iserver *server,
        gpdgc_process *process, unsigned long phi)
{
    UNUSED(server);
    UNUSED(phi);

    return process->current->decision;
}
GSList *gpdgc_extract_values(gpdgc_iserver *server, unsigned long phi,
        gpdgc_message *get_value(gpdgc_iserver *server, 
            gpdgc_process *process, unsigned long phi))
{
    GSList *result = NULL;
    GSList *iterator = server->servers;
    while (iterator != NULL)
    {
        gpdgc_process *iterated = iterator->data;
        iterator = iterator->next;

        gpdgc_message *message = get_value(server, iterated, phi);
        if (message != NULL)
        {
            result = g_slist_append(result, message);
        }
    }
    return result;
}


/* Clean history */
void gpdgc_clean_local_history(gpdgc_iserver *server, unsigned long phi)
{
    if (server->vote_history != NULL)
    {
        g_debug("%-10s: Clean history before round '%lu'", "CONSENSUS", phi);

        gpdgc_timed_vote *vote = server->vote_history->data;
        while ((vote != NULL)
                && (gpdgc_cmp_counter(vote->timestamp, phi) < 0))
        {
            server->vote_history = g_slist_remove(server->vote_history, vote);
            gpdgc_free_timed_vote(vote);

            vote = server->vote_history != NULL
                ? server->vote_history->data : NULL;
        }
    }
}
void gpdgc_clean_local_history_based_on_messages(gpdgc_iserver *server)
{
    /* Extract the messages that can be safely considered as honest */
    GSList *msgs = gpdgc_extract_values(server, 0, gpdgc_get_honest_value);
    if (msgs != NULL)
    {
        /* Find the maximum timestamp in this set of messages */
        int found = 0;
        unsigned long clean_phi = 0;

        GSList *iterator = msgs;
        while (iterator != NULL)
        {
            gpdgc_message *message = iterator->data;
            iterator = iterator->next;

            size_t size;
            unsigned long *ts = gpdgc_peek_content(message, 1, &size); 
            if ((size == sizeof(unsigned long))
                    && ((!found) || (gpdgc_cmp_counter(*ts, clean_phi) > 0)))
            {
                clean_phi = *ts;
                found = 1;
            }
        }
        g_slist_free(msgs);

        if (found)
        {
            gpdgc_clean_local_history(server, clean_phi);
        }
    }
}


/* Select the value having a quorum of the specified threshold */
void *gpdgc_get_quorum_value(GSList *values, unsigned int threshold,
        int select_only_if_single, size_t *size)
{
    void *result = NULL;
    *size = 0;

    GSList *iterator = values;
    while ((g_slist_length(iterator) > threshold)
            && ((result == NULL) || select_only_if_single))
    {            
        gpdgc_message *message = iterator->data;
        iterator = iterator->next;

        size_t value_size;
        void *value = gpdgc_peek_value(message, 0, &value_size); 

        if ((result == NULL)
                || (value_size != *size)
                || (memcmp(value, result, value_size) != 0))
        {
            unsigned int counter = threshold;
            GSList *other_iterator = iterator;
            while ((other_iterator != NULL) && (counter > 0))
            {
                gpdgc_message *other = other_iterator->data;
                other_iterator = other_iterator->next;

                size_t other_size;
                void *other_value = gpdgc_peek_value(other, 0, &other_size); 

                if ((other_size == value_size)
                        && (memcmp(value, other_value, value_size) == 0))
                {
                    counter --;
                }
            }

            if ((counter == 0) && (result == NULL))
            {	  
                result = value;
                *size = value_size;
            }
            else if (counter == 0)
            {
                /* Two different values reach the threshold */
                g_assert(select_only_if_single);
                *size = 0;
                return NULL;
            }
        }
    }  
    return result;
}


/* Select the value being valid according to history */
void *gpdgc_get_historically_valid_value(gpdgc_iserver *server, GSList *values,
        unsigned int threshold, int *select_any, size_t *size)
{
    void *result = NULL;
    *size = 0;

    GSList *iterator = values; 
    while (iterator != NULL)
    {
        gpdgc_message *message = iterator->data;
        iterator = iterator->next;

        size_t value_size;
        void *value = gpdgc_peek_value(message, 0, &value_size);

        size_t ts_size;
        unsigned long *ts = gpdgc_peek_content(message, 1, &ts_size);
        if ((ts_size == sizeof(unsigned long))
                && ((result == NULL)
                    || (*size != value_size)
                    || (memcmp(result, value, *size) != 0)))
        {
            int counter = threshold + 1;
            GSList *server_iterator = server->servers;
            while ((server_iterator != NULL) && (counter > 0))
            {
                gpdgc_process *server = server_iterator->data;
                server_iterator = server_iterator->next;

                if (server->current->decision != NULL)
                {
                    gpdgc_message *other = server->current->decision;
                    
                    size_t other_size;
                    void *other_value = gpdgc_peek_value(other, 0, &other_size);

                    if ((other_size == value_size)
                            && (memcmp(value, other_value, value_size) == 0))
                    {
                        counter --;
                    }
                }
                else if (server->current->message != NULL)
                {
                    gpdgc_message *other = server->current->message;
                    size_t size;
                    void *buffer = gpdgc_peek_content(other, 2, &size);

                    GSList *history = gpdgc_extract_history(buffer, size);
                    GSList *history_iterator = history;
                    while (history_iterator != NULL)
                    {
                        gpdgc_timed_vote *selection = history_iterator->data;
                        history_iterator = history_iterator->next;

                        if ((selection->timestamp == *ts)
                                && (selection->size == value_size)
                                && (memcmp(selection->vote, value,
                                        value_size) == 0))
                        {
                            counter --;
                            history_iterator = NULL;
                        }
                    }
                    g_slist_free_full(history, gpdgc_free_timed_vote);
                }
            }

            if ((counter == 0) && (result == NULL))
            {
                result = value;
                *size = value_size;
            }
            else if (counter == 0)
            {
                *select_any = 1;
                *size = 0;
                return NULL;
            }
        }
    }
    return result;
}


/* Select the smallest value from a set of messages */
void *gpdgc_select_deterministically_any_value_from_messages(GSList *messages,
        unsigned int nb_processes, unsigned int threshold, size_t *size)
{
    /* Init the value lists */
    GSList** values = calloc(nb_processes, sizeof(GSList *));
    if (values == NULL)
    {
        return NULL;
    }
    for (unsigned int i = 0; i < nb_processes; i++)
    {
        values[i] = NULL;
    }  

    /* Sort the values in the messages by processes */
    size_t expected_value_size = nb_processes * sizeof(unsigned long);
    unsigned int correct_messages_counter = 0;
    GSList *iterator = messages;
    while (iterator != NULL)
    {
        gpdgc_message *message = (gpdgc_message *) iterator->data;
        iterator = iterator->next;

        size_t value_size;
        unsigned long *value = gpdgc_peek_content(message, 0, &value_size);

        if (value_size == expected_value_size)
        {
            correct_messages_counter ++;
            for (unsigned int i = 0; i < nb_processes; i++)
            {
                values[i] = g_slist_insert_sorted(values[i], &value[i],
                        (int (*)(const void *, const void *))
                        gpdgc_cmp_counter_pointer);
            }
        }
    }

    /* Return the result, but only if it is valid */
    int result_is_valid = correct_messages_counter > threshold;
    for (unsigned int i = 0; result_is_valid && (i < nb_processes); i++)
    {
        result_is_valid = values[i] != NULL;
    }
    unsigned long *result = NULL;
    if (result_is_valid)
    {
        result = calloc(nb_processes, sizeof(unsigned long));
        if (result != NULL)
        {
            *size = expected_value_size;
            for (unsigned int i = 0; i < nb_processes; i++)
            {
                unsigned long *val = g_slist_nth(values[i], threshold)->data;
                result[i] = *val;
            }
        }
    }
    for (unsigned int i = 0; i < nb_processes; i++)
    {
        g_slist_free(values[i]);
    }
    free(values);
    return result;
}

/* Extract the locked value */
void *gpdgc_no_validation_flv(gpdgc_iserver *server,
        unsigned int nb_hos, unsigned int nb_decisions, unsigned int nb_servers,
        unsigned int max_faulty, int *select_any_value, size_t *size)
{
    g_debug("%-10s: No validation selection: (%d+%d)/%d messages (f = %d)",
            "CONSENSUS", nb_hos, nb_decisions, nb_servers, max_faulty);

    GSList *msgs = gpdgc_extract_values(server, 0, gpdgc_get_any_value);
    unsigned int threshold = (nb_servers - max_faulty - 1) / 2;
    void *select = gpdgc_get_quorum_value(msgs, threshold, 1, size);
    g_slist_free(msgs);

    unsigned int nb_msgs = nb_hos + nb_decisions;
    if ((select == NULL) && (nb_msgs > nb_servers - max_faulty - 1))
    {
        *select_any_value = 1;
    }
    return select;
}
void *gpdgc_amnesic_validation_flv(gpdgc_iserver *server,
        unsigned int nb_hos, unsigned int nb_decisions, unsigned int nb_servers,
        unsigned int max_faulty, int *select_any_value, size_t *size)
{
    g_debug("%-10s: Amnesic validation selection: (%d+%d)/%d messages (f = %d)",
            "CONSENSUS", nb_hos, nb_decisions, nb_servers, max_faulty);

    GSList *msgs = gpdgc_extract_values(server, 0, gpdgc_get_validated_value);
    unsigned int threshold = gpdgc_is_byzantine_model(server) ? max_faulty : 0;
    void *select = gpdgc_get_quorum_value(msgs, threshold, 1, size);
    g_slist_free(msgs);

    unsigned int nb_msgs = nb_hos + nb_decisions;
    if ((select == NULL) && (nb_msgs > nb_servers - max_faulty - 1))
    {
        *select_any_value = 1;
    }
    return select;
}
void *gpdgc_full_validation_flv(gpdgc_iserver *server,
        unsigned int nb_hos, unsigned int nb_decisions, unsigned int nb_servers,
        unsigned int max_faulty, int *select_any_value, size_t *size)
{
    g_debug("%-10s: Full validation selection: (%d+%d)/%d messages (f = %d)",
            "CONSENSUS", nb_hos, nb_decisions, nb_servers, max_faulty);

    GSList *msgs = gpdgc_extract_values(server, 0, gpdgc_get_validated_value);
    unsigned int threshold = gpdgc_is_byzantine_model(server) ? max_faulty : 0;
    void *select = gpdgc_get_historically_valid_value(server, msgs, threshold,
            select_any_value, size);
    g_slist_free(msgs);

    unsigned int nb_msgs = nb_hos + nb_decisions;
    if ((select == NULL) && (!*select_any_value))
    {
        GSList *init_msgs =
            gpdgc_extract_values(server, 0, gpdgc_get_phased_value);
        if (g_slist_length(init_msgs) >= gpdgc_get_validated_threshold(server))
        {
            GSList *any_msgs =
                gpdgc_extract_values(server, 0, gpdgc_get_any_value);
            select = gpdgc_get_quorum_value(any_msgs, nb_msgs/2, 0, size);
            if (select == NULL)
            {
                *select_any_value = 1;
            }
            g_slist_free(any_msgs);
        }
        g_slist_free(init_msgs);
    }
    return select;
}
void *gpdgc_extract_the_locked_value(gpdgc_iserver *server,
        unsigned long phase, unsigned long round, unsigned int nb_decisions,
        size_t *size)
{
    unsigned int nb_clients = g_slist_length(server->clients);
    unsigned int nb_servers = g_slist_length(server->servers);
    unsigned int max_faulty = gpdgc_get_max_faulty(server);

    /* Find the locked value */
    /* NB: select_any_value := nb_messages >= nb_servers - max_faulty */
    int select_any_value = 0;
    void *locked_value = NULL; 
    GSList *msgs = gpdgc_extract_values(server, 0, gpdgc_get_consistent_value); 
    unsigned int nb_msgs = g_slist_length(msgs);
    if (server->validation == GPDGC_NO_VALIDATION)
    {
        locked_value = gpdgc_no_validation_flv(server, nb_msgs,
                nb_decisions, nb_servers, max_faulty, &select_any_value, size);
    }
    if (server->validation == GPDGC_AMNESIC_VALIDATION)
    {
        locked_value = gpdgc_amnesic_validation_flv(server, nb_msgs,
                nb_decisions, nb_servers, max_faulty, &select_any_value, size);
    }
    if (server->validation == GPDGC_FULL_VALIDATION)
    {
        locked_value = gpdgc_full_validation_flv(server, nb_msgs,
                nb_decisions, nb_servers, max_faulty, &select_any_value, size);

        gpdgc_clean_local_history_based_on_messages(server);
    }

    /* Do a copy of the locked value */
    if (locked_value != NULL)
    {
        void *result = malloc(*size);
        if (result != NULL)
        {
            char *locked_label = gpdgc_get_vote_label(locked_value, *size);
            g_debug("%-10s: Select locked '%s' at round '%lu:%lu'",
                    "CONSENSUS", locked_label, phase, round);
            memcpy(result, locked_value, *size);
            g_slist_free(msgs);
            free(locked_label);
            return result;	  
        }
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Selection round '%lu:%lu': cannot select "
                "locked value", "CONSENSUS", phase, round);
    }
    else if (select_any_value)
    {
        unsigned int multiplier = gpdgc_is_byzantine_model(server)
            && (server->validation != GPDGC_FULL_VALIDATION) ? 2 : 1;
        unsigned int select_threshold = multiplier * max_faulty; 
        
        void *result = gpdgc_select_deterministically_any_value_from_messages(
                msgs, nb_clients + nb_servers, select_threshold, size);

        if (result != NULL)
        {
            char *any_value = gpdgc_get_vote_label(result, *size);
            g_debug("%-10s: Select any '%s' at round '%lu:%lu'",
                    "CONSENSUS", any_value, phase, round);
            g_slist_free(msgs);
            free(any_value);
            return result;
        }
    }
    g_slist_free(msgs);
    g_debug("%-10s: No value selected at round '%lu:%lu'",
            "CONSENSUS", phase, round);
    *size = 0;
    return NULL;
}


/* Send phase of the validation round */
int gpdgc_start_validation_round(gpdgc_iserver *server,
        unsigned long phase, unsigned long round,
        void *select, size_t select_size)
{ 
    gpdgc_process *coord = server->coordinator->data; 
    gpdgc_process *local = server->local;

    unsigned short flags = 0;
    if (server->election == GPDGC_ROTATING_COORDINATOR)
    {
        flags |= GPDGC_ROUND_COORDINATOR_ONLY_FLAG;
    }

    char *select_label = gpdgc_get_vote_label(select, select_size); 
    g_debug("%-10s: Send '%s' for validation at round '%lu:%lu'",
            "CONSENSUS", select_label, phase, round);
    free(select_label);
    gpdgc_message *message = NULL;
    if ((server->election == GPDGC_NO_ELECTION)
            || (gpdgc_cmp_address(coord->address, local->address) == 0))
    {
        message = gpdgc_create_message();
        if ((message == NULL)
                || (!gpdgc_push_content(message, select, select_size)))
        {      
            gpdgc_free_message(message);
            gpdgc_signal_lack_of_memory(server,
                    "%-10s: Validation round '%lu:%lu' cannot be initiated",
                    "CONSENSUS", phase, round);
            return -1;
        }
    }
    return gpdgc_start_heardof_round(server, phase, round, flags, message);
}

/* Send phase of the selection round */
gpdgc_message *gpdgc_build_selection_message(void *vote, size_t vote_size, 
        unsigned long ts, GSList *history, gpdgc_validation_type validation)
{
    gpdgc_message *msg = gpdgc_create_message();
    if (msg != NULL) 
    {
        if (validation == GPDGC_FULL_VALIDATION)
        {
            size_t buffer_size;
            void *buffer = gpdgc_write_history(history, &buffer_size);
            if ((history != NULL) && (buffer == NULL))
            {
                gpdgc_free_message(msg);
                return NULL;
            }

            int push_result = gpdgc_push_content(msg, buffer, buffer_size);
            free(buffer);
            if (!push_result)
            {
                gpdgc_free_message(msg);
                return NULL;
            }
        }

        if ((((validation == GPDGC_FULL_VALIDATION)
                        || (validation == GPDGC_AMNESIC_VALIDATION))
                    && (!gpdgc_push_content(msg, &ts, sizeof(unsigned long))))
                || (!gpdgc_push_content(msg, vote, vote_size))) 
        {
            gpdgc_free_message(msg);
            return NULL;
        }
    }
    return msg;
}
void gpdgc_rotate_coordinator(gpdgc_iserver *server)
{
    server->coordinator = server->coordinator->next;
    if (server->coordinator == NULL)
    {
        server->coordinator = server->servers;
    }
}
int gpdgc_start_selection_round(gpdgc_iserver *server,
        unsigned long phase, unsigned long round)
{
    /* Build the selection message */
    gpdgc_message *message =
        gpdgc_build_selection_message(server->vote, server->vote_size,
                server->vote_ts, server->vote_history, server->validation);
    if (message == NULL)
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Selection round '%lu:%lu' cannot be initiated",
                "CONSENSUS", phase, round);
        gpdgc_free_message(message);
        return -1;
    }

    /* Synchronize the round to the synchronized clock */
    gpdgc_process *sync = gpdgc_get_synchronized_server(server);
    if ((sync->phase == phase)
            && (gpdgc_cmp_counter(round + 1, sync->round) < 0))
    {
        g_debug("%-10s: Synchronize to round '%ld' (of '%s') from "
                "round '%ld'", "CONSENSUS", sync->round, sync->label, round);
        do 
        {
            round += 2;
            gpdgc_rotate_coordinator(server);
        }
        while (gpdgc_cmp_counter(round + 1, sync->round) < 0);
    }
    char *vote_label = gpdgc_get_vote_label(server->vote, server->vote_size);
    g_debug("%-10s: Send '%s'#'%lu' for selection at round '%lu:%lu'",
            "CONSENSUS", vote_label, server->vote_ts, phase, round);
    free(vote_label);

    /* Rotate the coordinator */
    gpdgc_rotate_coordinator(server);

    /* Start the heardof round */
    server->selection_flags |= round > 5 ? GPDGC_ROUND_CONSISTENT_FLAG : 0;
    return gpdgc_start_heardof_round(server, phase, round,
            server->selection_flags, message);
}  

/* Delivery phase of the validation round */
void gpdgc_free_current_round(gpdgc_iserver *server, int free_decisions)
{
    GSList *iterator = server->servers;
    while (iterator != NULL)
    {
        gpdgc_process *iterated = iterator->data;
        iterator = iterator->next;

        if (free_decisions)
        {
            gpdgc_free_message(iterated->current->decision);
            iterated->current->decision = NULL;
        }
        gpdgc_free_message(iterated->current->message);
        iterated->current->message = NULL;
        g_slist_free_full(iterated->current->votes, gpdgc_free_message);
        iterated->current->votes = NULL;
        iterated->current->counter = 0;
        iterated->current->flags = 0;
    }
}
unsigned int gpdgc_get_validation_threshold(gpdgc_iserver *server)
{
    if (server->election == GPDGC_NO_ELECTION)
    {
        unsigned int nb_servers = g_slist_length(server->servers);
        unsigned int max_byzantine = gpdgc_get_max_byzantine(server);

        return (nb_servers + max_byzantine) / 2;
    }
    return 0;
}
void gpdgc_deliver_validation_round(gpdgc_iserver *server,
        unsigned long phase, unsigned long round)
{
    GSList *msgs = gpdgc_extract_values(server, 0, gpdgc_get_any_value);
    size_t size;
    unsigned int threshold = gpdgc_get_validation_threshold(server);
    void *select = gpdgc_get_quorum_value(msgs, threshold, 0, &size);
    g_slist_free(msgs);

    if (select != NULL)
    {
        void *new_vote = malloc(size);
        if (new_vote == NULL)
        {
            gpdgc_signal_lack_of_memory(server,
                    "Validation round '%lu:%lu': could not store value",
                    "CONSENSUS", phase, round);
        }
        else
        {
            char *select_label= gpdgc_get_vote_label(select, size); 
            g_debug("%-10s: Value '%s' has been validated at round '%lu:%lu'",
                    "CONSENSUS", select_label, phase, round);
            free(select_label);
            free(server->vote);
            server->vote = new_vote;

            memcpy(server->vote, select, size);
            server->vote_size = size;
            server->vote_ts = (round + 2) / 2;	      

            gpdgc_clean_local_history(server, server->vote_ts);
        }
    }
    gpdgc_free_current_round(server, 0);
    gpdgc_start_selection_round(server, phase, round + 1);
}

/* Delivery phase of the selection round */
int gpdgc_cmp_timed_vote(const void *void_first, const void *void_second)
{
    const gpdgc_timed_vote *first = void_first;
    const gpdgc_timed_vote *second = void_second;

    return gpdgc_cmp_counter(first->timestamp, second->timestamp);
}
unsigned int gpdgc_get_decision_threshold(gpdgc_iserver *server)
{
    int is_byzantine = gpdgc_is_byzantine_model(server);
    unsigned int nb_servers = g_slist_length(server->servers);
    unsigned int max_faulty = gpdgc_get_max_faulty(server);
    if (is_byzantine)
    {
        if (server->validation == GPDGC_FULL_VALIDATION)
        {
            return 2 * max_faulty;
        }
        else if (server->validation == GPDGC_AMNESIC_VALIDATION)
        {
            return 3 * max_faulty;
        }
        return (nb_servers + 3 * max_faulty) / 2;
    }

    if (server->validation == GPDGC_NO_VALIDATION)
    {
        return (nb_servers + max_faulty) / 2;
    }
    return max_faulty;
}
int gpdgc_decide_value(gpdgc_iserver *server, unsigned long phase,
        void *decision, size_t decision_size)
{
    /* Clone the decision to deliver it */
    void *clone = malloc(decision_size);
    if (clone == NULL)
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Cannot clone decision '%lu'", "CONSENSUS", phase);
        return 0;
    }
    memcpy(clone, decision, decision_size);

    /* Backup the decision */
    gpdgc_timed_vote *backup = malloc(sizeof(gpdgc_timed_vote));
    if (backup != NULL)
    {
        backup->vote = malloc(decision_size);
    }
    if ((backup == NULL) || (backup->vote == NULL))
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Cannot backup decision '%lu'", "CONSENSUS", phase);
        free(clone);
        free(backup);
        return 0;
    }
    memcpy(backup->vote, decision, decision_size);
    backup->timestamp = phase;
    backup->size = decision_size;
    gpdgc_reserve_cache(server,
            sizeof(gpdgc_timed_vote) + decision_size + sizeof(GSList)); 
    server->previous_decisions = g_slist_insert_sorted(
            server->previous_decisions, backup, gpdgc_cmp_timed_vote);

    /* Reset the variables used for this consensus instance */
    free(server->vote);
    server->vote = NULL;
    server->vote_size = 0;
    server->vote_ts = 0;
    g_slist_free_full(server->vote_history, gpdgc_free_timed_vote);
    server->vote_history = NULL;

    /* Update the local clock and free current round */
    server->local->phase = phase + 1;
    server->local->round = 0;
    gpdgc_free_current_round(server, 1);
    gpdgc_clean_cache(server);

    /* Return the decison */
    gpdgc_deliver_decision(server, phase, (unsigned long *) clone);
    return 1;
}
void gpdgc_deliver_selection_round(gpdgc_iserver *server,
        unsigned int nb_decisions, unsigned long phase, unsigned long round)
{
    /* Try to decide on a value */
    unsigned long phi = (round + 1) / 2;
    GSList *msgs = (server->validation == GPDGC_NO_VALIDATION)
        ? gpdgc_extract_values(server, phi, gpdgc_get_any_value)
        : gpdgc_extract_values(server, phi, gpdgc_get_phased_value);  
    size_t decision_size;
    unsigned int threshold = gpdgc_get_decision_threshold(server);
    void *decision = gpdgc_get_quorum_value(msgs, threshold, 0, &decision_size);
    g_slist_free(msgs);

    if (decision != NULL)
    {
        char *decision_label = gpdgc_get_vote_label(decision, decision_size); 
        g_debug("%-10s: Decides value '%s' at round '%lu:%lu'",
                "CONSENSUS", decision_label, phase, round);
        free(decision_label);

        if (gpdgc_decide_value(server, phase, decision, decision_size))
        {
            return;
        }
    }
    else 
    {
        g_debug("%-10s: No value can be decided at round '%lu:%lu'",
                "CONSENSUS", phase, round);
    }

    /* No decision has been made, select a value for a new trial */
    size_t selection_size;
    void *selection = gpdgc_extract_the_locked_value(server,
            phase, round, nb_decisions, &selection_size);
    if ((selection != NULL) && (server->validation == GPDGC_FULL_VALIDATION))
    {
        /* Store the selected value in the history */
        gpdgc_timed_vote *historized = malloc(sizeof(gpdgc_timed_vote));
        if (historized == NULL)
        {
            free(selection);
            gpdgc_signal_lack_of_memory(server,
                    "%-10s: Selection round '%lu:%lu': cannot historize "
                    "value", "CONSENSUS", phase, round);
        }
        else
        {
            historized->vote = selection;
            historized->size = selection_size;
            historized->timestamp = phi + 1;
            server->vote_history =
                g_slist_append(server->vote_history, historized);
            char *selection_label =
                gpdgc_get_vote_label(selection, selection_size); 
            g_debug("%-10s: Historize selected value '%s' at round '%lu:%lu'",
                    "CONSENSUS", selection_label, phase, round);
            free(selection_label);
        }      
    }
    else if ((selection != NULL) && (server->validation == GPDGC_NO_VALIDATION))
    {
        /* Set the selected value as the local current vote */
        free(server->vote);
        server->vote = selection;
        server->vote_size = selection_size;
        char *selection_label = gpdgc_get_vote_label(selection, selection_size); 
        g_debug("%-10s: Update vote with value '%s' at round '%lu:%lu'",
                "CONSENSUS", selection_label, phase, round);
        free(selection_label);
    }

    /* Skip validation when the process is late */
    int skipValidation = server->validation == GPDGC_NO_VALIDATION;
    if (!skipValidation)
    {
        gpdgc_process *sync = gpdgc_get_synchronized_server(server);
        if ((sync->phase == phase)
                && (gpdgc_cmp_counter(round + 1, sync->round) < 0))
        {
            g_debug("%-10s: Skip validation round '%ld' "
                    "(synchronized process '%s' is in round '%ld')",
                    "CONSENSUS", round + 1, sync->label, sync->round);
            skipValidation = 1;
        }
    }

    /* Start the next round */
    gpdgc_free_current_round(server, 0);
    if (skipValidation)
    {
        gpdgc_start_selection_round(server, phase, round + 2);
    }
    else
    {
        gpdgc_start_validation_round(server, phase, round + 1,
                selection, selection_size);
    }
    if (server->validation == GPDGC_AMNESIC_VALIDATION)
    {
        free(selection);
    }
}


/* Start a consensus instance */
int gpdgc_start_consensus(gpdgc_iserver *server,
        unsigned long phase, unsigned long *values)
{
    g_assert(server->vote == NULL);
    g_assert(phase == server->local->phase);

    /* Init the state of the consensus */
    unsigned int nb_processes = g_slist_length(server->servers)
         + g_slist_length(server->clients);
    server->vote = (void *) values;
    server->vote_size = nb_processes * sizeof(unsigned long);
    server->vote_ts = 0;
    if (server->validation == GPDGC_FULL_VALIDATION)
    {
        gpdgc_timed_vote *historized = malloc(sizeof(gpdgc_timed_vote));
        if (historized == NULL)
        {
            server->vote = NULL;
            gpdgc_signal_lack_of_memory(server,
                    "%-10s: The consensus instance '%lu' cannot be started",
                    "CONSENSUS", phase);
            return -1;      	  
        }
        historized->timestamp = 1;
        historized->size = server->vote_size;
        historized->vote = malloc(server->vote_size);
        if (historized->vote == NULL)
        {
            server->vote = NULL;
            free(historized);
            gpdgc_signal_lack_of_memory(server, 
                    "%-10s: The consensus instance '%lu' cannot be started", 
                    "CONSENSUS", phase);
            return -1;      
        }
        memcpy(historized->vote, server->vote, server->vote_size);

        server->vote_history = g_slist_append(server->vote_history, historized);
    }

    /* Start the round according to the consensus class */
    char *vote_label = gpdgc_get_vote_label(server->vote, server->vote_size); 
    g_debug("%-10s: Start consensus '%lu' with value '%s'",
            "CONSENSUS", phase, vote_label);
    free(vote_label);

    server->coordinator = server->servers;
    server->selection_flags = 0;
    if (server->validation != GPDGC_NO_VALIDATION)
    {
        return gpdgc_start_validation_round(server, phase, 0,
                server->vote, server->vote_size);
    }
    return gpdgc_start_selection_round(server, phase, 1);
}


/* Signal that a set of heard-of messages is ready for consensus */
void gpdgc_deliver_heardof_round(gpdgc_iserver *server, 
        unsigned long phase, unsigned long round)
{
    unsigned int threshold = gpdgc_get_max_byzantine(server); 
    GSList *msgs = gpdgc_extract_values(server, 0, gpdgc_get_decision_value);
    size_t size = 0;
    void *decision = gpdgc_get_quorum_value(msgs, threshold, 0, &size);
    unsigned int nb_decisions = g_slist_length(msgs);
    g_slist_free(msgs);

    /* Decide whenever it is possible */
    if (decision != NULL)
    {
        char *decision_label = gpdgc_get_vote_label(decision, size); 
        g_debug("%-10s: Decides value '%s' at round '%lu:-'",
                "CONSENSUS", decision_label, phase);
        free(decision_label);

        if (gpdgc_decide_value(server, phase, decision, size))
        {
            return;
        }
    }

    /* Process the round messages */
    if (round % 2 == 1)
    {
        gpdgc_deliver_selection_round(server, nb_decisions, phase, round);
    }
    else
    {
        gpdgc_deliver_validation_round(server, phase, round);
    }
}


/* Get the specified phase decision */
gpdgc_message *gpdgc_get_decision(gpdgc_iserver *server, unsigned long phase)
{
    GSList* iterator = server->previous_decisions;
    while ((iterator != NULL)
            && (gpdgc_cmp_counter(
                    ((gpdgc_timed_vote *) iterator->data)->timestamp,
                    phase) < 0))
    {
        iterator = iterator->next;
    }

    gpdgc_message *result = NULL;
    gpdgc_timed_vote *decision =
        iterator != NULL ? (gpdgc_timed_vote *) iterator->data : NULL;
    if ((decision != NULL) && (decision->timestamp == phase))
    {
        result = gpdgc_build_selection_message(decision->vote,
                decision->size, 0, NULL, server->validation);
        if (result == NULL)
        {
            gpdgc_signal_lack_of_memory(server,
                    "%-10s: Decision for phase '%lu' cannot be built", 
                    "CONSENSUS", phase);
        }
    }
    return result;
}
