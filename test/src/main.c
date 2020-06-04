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
#include <gcrypt.h>
#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>

#include <gpdgc.h>

#define KEY_BUFFER_LENGTH 65536
#define LAST_MESSAGE "FINISHED"
#define MESSAGE_SIZE 50 

gpdgc_server server;
gpdgc_client client;

FILE *log_file;
unsigned short excluded = 0;
unsigned short nb_received_messages = 0;
GSList *clients = NULL;
GSList *replies = NULL;
GSList *terminated = NULL;

/* Manage keys */
gcry_sexp_t clone_gcry_sexp_t(gcry_sexp_t original)
{
    size_t buffer_size =
        gcry_sexp_sprint(original, GCRYSEXP_FMT_CANON, NULL, 0);
    void *buffer = malloc(buffer_size);
    if (buffer == NULL)
    {
        return NULL;
    }
    
    size_t size =
        gcry_sexp_sprint(original, GCRYSEXP_FMT_CANON, buffer, buffer_size);
    if ((size == 0) || (buffer_size < size))
    {
        g_error("Clone S-Exp: invalid buffer size for S-Exp; "
                "expected=%ld used=%ld", buffer_size, size);
        size = 0;
        free(buffer);
        return NULL;
    }

    gcry_sexp_t result = NULL;
    if (gcry_sexp_new(&result, buffer, size, 0))
    {
        g_error("Clone S-Exp: invalid S-Exp in buffer");
    }
    free(buffer);
    return result;
}
gcry_sexp_t read_key(char *filename)
{  
    FILE* file = fopen(filename, "rb");
    if (file == NULL)
    {
        fprintf(stderr, "read_key: cannot open file '%s'!\n", filename);
        exit(1);
    }

    gcry_sexp_t key;
    void* key_buf = calloc(1, KEY_BUFFER_LENGTH);
    size_t key_read = fread(key_buf, 1, KEY_BUFFER_LENGTH, file);
    int failure = (key_read == 0) || gcry_sexp_new(&key, key_buf, key_read, 0);
    free(key_buf);
    return failure ? NULL : key;
}
gcry_sexp_t read_key_from_file(char *filename, char *src_filename)
{
    char *rootpath = g_path_get_dirname(src_filename);
    char *key_filename =
        calloc(strlen(rootpath) + strlen(filename) + 2, sizeof(char));

    memcpy(key_filename, rootpath, strlen(rootpath));
    key_filename[strlen(rootpath)] = '/';
    memcpy(key_filename + strlen(rootpath) + 1, filename, strlen(filename));
    key_filename[strlen(rootpath) + strlen(filename) + 1] = '\0';

    gcry_sexp_t public_key = read_key(key_filename);
    free(key_filename);
    free(rootpath);

    return public_key;
}


/* Manage addresses */
struct sockaddr_in *clone_address(struct sockaddr_in *address)
{
    size_t size = sizeof(struct sockaddr_in);
    struct sockaddr_in *result = malloc(size);
    if (result != NULL)
    {
        memcpy(result, address, size);
    }
    return result;
}
int cmp_address(struct sockaddr_in *first, struct sockaddr_in *second)
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
    return memcmp(first, second, sizeof(struct sockaddr_in));
}
int contains_address(GSList *addresses, struct sockaddr_in *address)
{
    GSList *iterator = addresses;
    while (iterator != NULL)
    {
        if (cmp_address(address, (struct sockaddr_in *) iterator->data) == 0)
        {
            return 1;
        }
        iterator = iterator->next;
    }
    return 0;
}
gcry_sexp_t retrieve_public_key(struct sockaddr_in *process,
        GSList *processes, GSList *public_keys)
{
    GSList *process_iterator = processes;
    GSList *key_iterator = public_keys;
    while ((process_iterator != NULL) && (key_iterator != NULL))
    {
        struct sockaddr_in *iterated = process_iterator->data;
        process_iterator = process_iterator->next;

        gcry_sexp_t key = key_iterator->data;
        key_iterator = key_iterator->next;

        if (cmp_address(process, iterated) == 0)
        {
            return key;
        }
    }
    return NULL;
}
char *get_address_label(struct sockaddr_in *address)
{
    char *label = malloc(INET_ADDRSTRLEN);
    short port = -1;
    if (label != NULL)
    {
        inet_ntop(address->sin_family, &address->sin_addr,
                label, INET6_ADDRSTRLEN);
        port = ntohs(address->sin_port);
    }

    char *result = NULL;
    if (port >= 0)
    {
        asprintf(&result, "%s:%d", label, port);
    }
    free(label);
    return result; 
}
struct sockaddr_in *read_address(char *server)
{
    /* Find the semi-column in the line */
    unsigned int i, j;
    for (i=0; (server[i] != ':')
            && (server[i] != '\n') && (server[i] != '\0'); i++) { }
    if (server[i] != ':')
    {
        fprintf(stderr, "read_address: invalid string '%s'!\n", server); 
        exit(1);
    }
    for (j=i+1; (server[j] != ' ')
            && (server[j] != ',') && (server[j] != ';')
            && (server[j] != '\n') && (server[j] != '\0'); j++) { }

    char *address = calloc(i+1, sizeof(char)); 
    if (address == NULL)
    {
        fprintf(stderr, "read_address: lack of memory to read address!\n");
        exit(1);
    }
    memcpy(address, server, i);
    address[i] = '\0';

    char *port_string = malloc(sizeof(char)*(j-i));
    if (port_string == NULL)
    {
        fprintf(stderr, "read_address: lack of memory to read port!\n");
        exit(1);
    }
    memcpy(port_string, server+i+1, (j-i-1));
    port_string[j-i-1] = '\0';
    int port = strtol(port_string, (char **)NULL, 10); 

    struct sockaddr_in *result = malloc(sizeof(struct sockaddr_in));
    if (result == NULL)
    {
        fprintf(stderr, "read_address: lack of memory to build the result!\n");
        exit(1);
    }

    memset(result, 0, sizeof(struct sockaddr_in));
    result->sin_family = AF_INET;
    result->sin_port = htons(port);

    if (inet_pton(AF_INET, address, &result->sin_addr) == 0)
    {
        fprintf(stderr, "read_address: cannot read address '%s'!\n", address);
        exit(1);
    }
    free(address);
    free(port_string);
    return (struct sockaddr_in *)result;
}


/* Read global parameters */
char *extract_sub_string(char *string, unsigned int start, unsigned int length)
{
    char *result = calloc(length + 1, sizeof(char));
    if (result == NULL)
    {
        fprintf(stderr, "read_processes: lack of memory!\n");
        exit(1);
    }
    memcpy(result, string + start, length);
    result[length] = '\0';

    return result;
}
int read_params(char *filename,
        gpdgc_channel_fault_model *channel, gpdgc_process_fault_model *process,
        gpdgc_validation_type *validation, gpdgc_election_type *election,
        gcry_sexp_t *trusted_key_private, gcry_sexp_t *trusted_key_public)
{
    FILE* file = fopen(filename, "rb");
    if (file == NULL)
    {
        fprintf(stderr, "read_model: cannot open file '%s'!\n", filename);
        exit(1);
    }

    const unsigned int LINE_SIZE = 256;
    char line[LINE_SIZE];
    int load_keys = 0;

    *channel = GPDGC_SECURE_MODEL;
    if (fgets(line, LINE_SIZE, file))
    {
        if (strncasecmp(line, "corrupted-channels", 18) == 0)
        {
            *channel = GPDGC_CORRUPTED_MODEL;
            load_keys = 1;
        }
    }

    *process = GPDGC_CRASH_STOP_MODEL;
    if (fgets(line, LINE_SIZE, file))
    {
        if (strncasecmp(line, "byzantine-with-signatures", 25) == 0)
        {
            *process = GPDGC_BYZANTINE_MODEL;
            load_keys = 1;
        }
        else if (strncasecmp(line, "byzantine-without-signatures", 28) == 0)
        {
            *process = GPDGC_BYZANTINE_MODEL;
        }
    }

    *validation = GPDGC_NO_VALIDATION;
    if (fgets(line, LINE_SIZE, file))
    {
        if (strncasecmp(line, "amnesic-validation", 18) == 0)
        {
            *validation = GPDGC_AMNESIC_VALIDATION;
        }
        else if (strncasecmp(line, "full-validation", 15) == 0)
        {
            *validation = GPDGC_FULL_VALIDATION;
        }
    }

    *election = GPDGC_NO_ELECTION;
    if (fgets(line, LINE_SIZE, file))
    {
        if (strncasecmp(line, "rotating-coordinator", 20) == 0)
        {
            *election = GPDGC_ROTATING_COORDINATOR;
        }
    }

    *trusted_key_private = NULL;
    *trusted_key_public = NULL;
    if (fgets(line, LINE_SIZE, file) && (*process == GPDGC_BYZANTINE_MODEL))
    {
        unsigned int i, j;
        for (i=0; (line[i] != ';')
                && (line[i] != '\n') && (line[i] != '\0'); i++) { }
        if (line[i] != ';')
        {
            fprintf(stderr, "cannot read trusted from file '%s'!\n", filename);
            exit(1);
        }
        for (j=i+1; (line[j] != '\n') && (line[j] != '\0'); j++) { }

        char *public_filename = extract_sub_string(line, i + 1, j - i -1);
        *trusted_key_public = read_key_from_file(public_filename, filename);
        free(public_filename);

        char *private_filename = extract_sub_string(line, 0, i);
        *trusted_key_private = read_key_from_file(private_filename, filename);
        free(private_filename);
    }
    fclose(file);
    return load_keys;
}


/* Read scenario */
typedef struct
{
    unsigned int nb_abcast;
    unsigned int nb_rbcast;
    unsigned int crash;
    unsigned int break_duration;

    GSList *add_processes;
    GSList *remove_processes;
    GSList *update_keys;
} scenario_block;
scenario_block *create_scenario_block()
{
    scenario_block *result = malloc(sizeof(scenario_block));
    if (result != NULL)
    {
        result->nb_abcast = 0;
        result->nb_rbcast = 0;
        result->break_duration = 0;
        result->crash = 0;

        result->add_processes = NULL;
        result->remove_processes = NULL;
        result->update_keys = NULL;
    }
    return result;
}
void free_scenario_block(void *block_void)
{
    scenario_block *block = block_void;

    g_slist_free_full(block->add_processes, free);
    g_slist_free_full(block->remove_processes, free);
    g_slist_free_full(block->update_keys, (void (*)(void *))gcry_sexp_release);
    free(block);
}
GSList *read_scenario(char *filename, char *src_filename, int allow_rbcast)
{
    char *rootpath = g_path_get_dirname(src_filename);
    char *scenario_filename =
        calloc(strlen(rootpath) + strlen(filename) + 2, sizeof(char));

    memcpy(scenario_filename, rootpath, strlen(rootpath));
    scenario_filename[strlen(rootpath)] = '/';
    memcpy(scenario_filename + strlen(rootpath) + 1, filename, strlen(filename));
    scenario_filename[strlen(rootpath) + strlen(filename) + 1] = '\0';

    GSList *result = NULL;
    FILE* file = fopen(scenario_filename, "rb");
    if (file == NULL)
    {
        fprintf(stderr, "read_scenario: cannot open file '%s'!\n",
                scenario_filename);
        exit(1);
    }
    
    const unsigned int LINE_SIZE = 256;
    char line[LINE_SIZE];
    scenario_block *block = create_scenario_block();
    while(fgets(line, LINE_SIZE, file))
    {
        if (line[0] == '-')
        {
            result = g_slist_append(result, block);
            block = create_scenario_block();
        }
        else if ((line[0] != '#') && (line[0] != ' ') && (line[0] != '\0'))
        {
            unsigned int i, j;
            for (i=0; (line[i] != ' ')
                    && (line[i] != '\0') && (line[i] != '\n'); i++) { }
            for (j=i+1; (line[j] != ' ')
                    && (line[j] != '\0') && (line[j] != '\n'); j++) { }

            if ((strncasecmp(line, "ABCAST", i) == 0)
                    || ((!allow_rbcast)
                        && (strncasecmp(line, "RBCAST", i) == 0)))
            {
                int nb_messages = strtol(line+i+1, (char **)NULL, 10); 
                block->nb_abcast += nb_messages;
            }
            else if (strncasecmp(line, "RBCAST", i) == 0)
            {
                int nb_messages = strtol(line+i+1, (char **)NULL, 10); 
                block->nb_rbcast += nb_messages;
            }
            else if (strncasecmp(line, "ADD", i) == 0)
            {
                struct sockaddr_in *process = read_address(line+i+1);
                block->add_processes =
                    g_slist_append(block->add_processes, process);
            }
            else if (strncasecmp(line, "CRASH", i) == 0)
            {
                block->crash = 1;
            }
            else if (strncasecmp(line, "PAUSE", i) == 0)
            {
                int nb_millis = strtol(line+i+1, (char **)NULL, 10);
                block->break_duration = nb_millis;
            }
            else if (strncasecmp(line, "REMOVE", i) == 0)
            {
                struct sockaddr_in *process = read_address(line+i+1);
                block->remove_processes =
                    g_slist_append(block->remove_processes, process);
            }
            else if (strncasecmp(line, "UPDATE-KEY", i) == 0)
            {
                char *key_filename = extract_sub_string(line, i + 1, j - i -1);
                gcry_sexp_t trusted_key =
                    read_key_from_file(key_filename, scenario_filename);
                free(key_filename);

                block->update_keys =
                    g_slist_append(block->update_keys, trusted_key);
            }
        }
    }
    result = g_slist_append(result, block);
    free(scenario_filename);
    free(rootpath);
    fclose(file);
    return result;
}


/* Read processes */
void read_processes(char *filename, struct sockaddr_in *local, int *tick_length,
        GSList **scenario, GSList **processes, GSList **public_keys,
        GSList **init_view, GSList **init_keys, GSList **corrects,
        GSList **clients, int allow_rbcast)
{
    FILE* file = fopen(filename, "rb");
    if (file == NULL)
    {
        fprintf(stderr, "read_processes: cannot open file '%s'!\n", filename);
        exit(1);
    }

    const unsigned int LINE_SIZE = 256;
    char line[LINE_SIZE];
    while(fgets(line, LINE_SIZE, file))
    {
        if (line[0] != '#')
        {
            unsigned int i, j, k, l, m, n;
            for (i=0; (line[i] != ';')
                    && (line[i] != '\n') && (line[i] != '\0'); i++) { }
            if (line[i] != ';')
            {
                fprintf(stderr, "Invalid process file '%s'!\n", filename);
                exit(1);
            }
            for (j=i+1; (line[j] != ';')
                    && (line[j] != '\n') && (line[j] != '\0'); j++) { }
            if (line[j] != ';')
            { 
                fprintf(stderr, "Invalid process file '%s'!\n", filename);
                exit(1);
            }
            for (k=j+1; (line[k] != ';')
                    && (line[k] != '\n') && (line[k] != '\0'); k++) { }
            if (line[k] != ';')
            {
                fprintf(stderr, "Invalid process file '%s'!\n", filename);
                exit(1);
            }
            for (l=k+1; (line[l] != ';')
                    && (line[l] != '\n') && (line[l] != '\0'); l++) { }
            if ((line[l] != ';') || (l - k != 2))
            {
                fprintf(stderr, "Invalid process file '%s'!\n", filename);
                exit(1);
            }
            for (m=l+1; (line[m] != ';')
                    && (line[m] != '\n') && (line[m] != '\0'); m++) { }
            if (line[m] != ';')
            {
                fprintf(stderr, "Invalid process file '%s'!\n", filename);
                exit(1);
            }
            for (n=m+1; (line[n] != ';')
                    && (line[n] != '\n') && (line[n] != '\0'); n++) { }
            if (line[n] != ';')
            {
                fprintf(stderr, "Invalid process file '%s'!\n", filename);
                exit(1);
            }

            struct sockaddr_in *process = read_address(line);
            *processes = g_slist_append(*processes, process);

            char *key_filename = extract_sub_string(line, j+1, k-j-1);
            gcry_sexp_t public_key = read_key_from_file(key_filename, filename);
            free(key_filename);
            if (public_keys != NULL)
            {
                *public_keys = g_slist_append(*public_keys, public_key);
            }
            else
            {
                gcry_sexp_release(public_key);
                public_key = NULL;
            }

            if (line[k+1] == 'I')
            {
                *init_view = g_slist_append(*init_view, clone_address(process));
                if (init_keys != NULL)
                {
                    *init_keys = g_slist_append(*init_keys,
                            clone_gcry_sexp_t(public_key));
                }
            }
            else if (line[k+1] == 'C')
            {
                *clients = g_slist_append(*clients, clone_address(process));
            }

            int tmp_tick_length = strtol(line+l+1, (char **)NULL, 10); 
            char *scenario_filename = extract_sub_string(line, m+1, n-m-1);
            GSList *tmp_scenario =
                read_scenario(scenario_filename, filename, allow_rbcast);
            free(scenario_filename);

            int crashes = 0;
            GSList *iterator = tmp_scenario;
            while (iterator != NULL)
            {
                scenario_block *block = iterator->data;
                iterator = iterator->next;

                crashes = crashes || block->crash;
            }
            
            if (cmp_address(process, local) == 0)
            {
                *tick_length = tmp_tick_length;
                *scenario = tmp_scenario;
            }
            else
            {
                g_slist_free_full(tmp_scenario, free_scenario_block);
            }

            if ((!crashes)
                    && (strcasestr(line+n+1, "corrupted") == NULL)
                    && (strcasestr(line+n+1, "malicious") == NULL))
            {
                *corrects = g_slist_append(*corrects, process);
            }
        }
    }
}


/* Methods to manage GPDGC Callback */
void callback_adeliver(struct sockaddr *sender, unsigned long id,
        void *message, size_t size)
{  
    struct sockaddr_in *isender = (struct sockaddr_in *)sender;
    if (size != MESSAGE_SIZE)
    {
        printf("   ERROR: unexpected msg size %ld!=%d\n", size, MESSAGE_SIZE);
    }
    else if (strcmp((char *)message, LAST_MESSAGE) == 0)
    {
        terminated = g_slist_append(terminated, clone_address(isender));
    }
    else
    {
        char *label = get_address_label(isender);
        printf("Adeliver '%s' identified by '%s:%ld'\n",
                (char *)message, label, id);
        fflush(stdout);
        free(label);

        if ((server != NULL) && contains_address(clients, isender))
        {
            gpdgc_send_reply_to_client(server, id, message, size, sender); 
        }
        nb_received_messages++;
    }
    free(message);
}
void callback_rdeliver(struct sockaddr *sender, unsigned long id,
        void *message, size_t size)
{  
    struct sockaddr_in *isender = (struct sockaddr_in *)sender;
    if (size != MESSAGE_SIZE)
    {
        printf("   ERROR: unexpected msg size %ld!=%d\n", size, MESSAGE_SIZE);
    }
    else
    {
        char *label = get_address_label(isender);
        printf("Rdeliver '%s' identified by '%s:%ld'\n",
                (char *)message, label, id);
        fflush(stdout);
        free(label);

        if ((server != NULL) && contains_address(clients, isender))
        {
            gpdgc_send_reply_to_client(server, id, message, size, sender); 
        }
        nb_received_messages++;
    }
    free(message);
}
int cmp_reply_id(const void *void_first, const void *void_second)
{
    const unsigned long *first = void_first;
    const unsigned long *second = void_second;

    if (*first == *second)
    {
        return 0;
    }
    return *first > *second ? 1 : -1;
}
void callback_deliver(unsigned long id, void *message, size_t size)
{
    if (size != MESSAGE_SIZE)
    {
        printf("   ERROR: unexpected msg size %ld!=%d\n", size, MESSAGE_SIZE);
    }
    else
    {
        GSList *iterator = replies;
        while (iterator != NULL)
        {
            unsigned long *iterated = iterator->data;
            iterator = iterator->next;

            if (*iterated == id)
            {
                replies = g_slist_remove(replies, iterated);
                free(iterated);
            }
        }

        printf("Deliver reply '%lu':'%s'\n", id, (char *)message);
        fflush(stdout);
        nb_received_messages++;
    }
    free(message);
}
void print_servers(GSList *servers)
{
    GSList *iterator = servers;
    while (iterator != NULL)
    {
        char *label = get_address_label((struct sockaddr_in *)iterator->data);
        iterator = iterator->next;

        printf("'%s' ", label);
        free(label);
    }
    printf("\n");
    g_slist_free(servers);
}
void print_byzantine_suspiscions()
{
    GSList *servers = server != NULL
        ? gpdgc_get_byzantine_suspiscions(server)
        : gpdgc_get_observed_byzantine_suspiscions(client);
    print_servers(servers);
}
void print_crash_suspiscions()
{
    GSList *servers = server != NULL
        ? gpdgc_get_crash_suspiscions(server)
        : gpdgc_get_observed_crash_suspiscions(client);
    print_servers(servers);
}
void print_current_view()
{
    GSList *servers = server != NULL
        ? gpdgc_get_current_view(server)
        : gpdgc_get_current_observed_view(client);
    print_servers(servers);
}
void callback_inform(gpdgc_event event)
{
    switch(event)
    {
        case GPDGC_NEW_TRUSTED_KEY:
            {
                printf("The trusted key has been updated !\n");
                break;
            }
        case GPDGC_OUT_OF_MEMORY:
            {
                printf("OUT OF MEMORY !\n");
                break;
            }
        case GPDGC_SUSPISCION:
            {
                printf("Byzantine suspiscions: ");
                print_byzantine_suspiscions();
                printf("Crashed suspiscions: ");
                print_crash_suspiscions();
                break;
            }
        case GPDGC_VIEW_EXCLUSION:
            {
                printf("Server has been excluded from view !\n");
                excluded = 1;
                break;
            }
        case GPDGC_VIEW_INIT:
            {
                printf("Initial view has been installed: ");
                print_current_view();
                break;
            }
        case GPDGC_VIEW_UPDATE:
            {
                printf("View has been updated: ");
                print_current_view();
                break;
            }
    }
    fflush(stdout);
}


/* Methods for logging */
void main_log_handler(const gchar *log_domain, GLogLevelFlags log_level,
        const gchar *message, gpointer user_data)
{
    (void)(log_domain); // Unused 
    (void)(user_data);  // Unused

    if (log_file != NULL)
    {
        /* Retrieve log time */
        time_t now;
        time(&now);
        char *now_as_string = ctime(&now);
        now_as_string[strlen(now_as_string) - 1] = '\0';

        /* Print the log in file and free resources */
        char *sLevel;
        switch (log_level)
        {
            case G_LOG_LEVEL_ERROR:
                sLevel="[ERROR]   "; break;
            case G_LOG_LEVEL_CRITICAL:
                sLevel="[CRITICAL]"; break;
            case G_LOG_LEVEL_WARNING:
                sLevel="[WARNING] "; break;
            case G_LOG_LEVEL_MESSAGE:
                sLevel="[MESSAGE] "; break;
            case G_LOG_LEVEL_INFO:
                sLevel="[INFO]    "; break;
            case G_LOG_LEVEL_DEBUG:
                sLevel="[DEBUG]   "; break;
            default:
                sLevel="[UNKNOWN] "; break;
        }
        fprintf(log_file, "%s %s %s\n", now_as_string, sLevel, message);
        fflush(log_file);
    }
}

/* Methods to check end of program */
int check_pending_replies(unsigned long highest_pending_rid,
        unsigned short max_pending_replies)
{
    GSList *iterator = replies;
    while (iterator != NULL)
    {
        unsigned long *rid = iterator->data;
        iterator = iterator->next;

        if ((*rid + max_pending_replies - 1) <= highest_pending_rid)
        {
            return 0;
        }
    }
    return 1;
}
int deserved_all_clients(gpdgc_server server)
{
    GSList *tmp = gpdgc_get_current_clients(server);
    int result = g_slist_length(tmp) == 0;
    g_slist_free(tmp);

    return result;
}
int received_all_messages(GSList *terminated, GSList *corrects,
        gpdgc_server server)
{
    int result = 1;
    GSList *view = gpdgc_get_current_view(server);
    GSList *iterator = view;
    while (result && (iterator != NULL))
    {
        struct sockaddr_in *srv = iterator->data;
        iterator = iterator->next;

        result = (!contains_address(corrects, srv)) 
            || contains_address(terminated, srv);
    }
    g_slist_free(view);
    return result;
}

/* Main method*/
int main(int argc, char *argv[])
{  
    /* Check program arguments */
    if (argc != 7)
    {
        fprintf(stderr, "%d arguments, expected 7!\n", argc);
        fflush(stderr);
        exit(1);
    }

    /* Init the gcrypt library */
    if (!gcry_check_version (GCRYPT_VERSION))
    {
        fprintf(stderr, "libgcrypt version mismatch\n");
        fflush(stderr);
        exit(2);
    }
    gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    /* Read the parameters */
    struct sockaddr_in *self_address = read_address(argv[1]);

    gpdgc_channel_fault_model channel_model = GPDGC_SECURE_MODEL;
    gpdgc_process_fault_model process_model = GPDGC_CRASH_STOP_MODEL;
    gpdgc_validation_type validation = GPDGC_NO_VALIDATION;
    gpdgc_election_type election = GPDGC_NO_ELECTION;
    gcry_sexp_t private_trusted_key = NULL;
    gcry_sexp_t trusted_key = NULL;
    int load_keys = read_params(argv[5], &channel_model, &process_model,
            &validation, &election, &private_trusted_key, &trusted_key);
    int allow_rbcast = (process_model == GPDGC_CRASH_STOP_MODEL)
        || (validation != GPDGC_FULL_VALIDATION);

    int tick_length = 0;
    GSList *processes = NULL;
    GSList *public_keys = NULL;
    GSList *init_view = NULL;
    GSList *init_keys = NULL;
    GSList *corrects = NULL;
    GSList *scenario = NULL;
    read_processes(argv[4], self_address, &tick_length, &scenario,
            &processes, load_keys ? &public_keys : NULL,
            &init_view, load_keys ? &init_keys : NULL,
            &corrects, &clients, allow_rbcast);

    int is_local_client = contains_address(clients, self_address);
    int is_local_in_initial_view = contains_address(init_view, self_address);
    int is_local_faulty = !contains_address(corrects, self_address);
    if (is_local_client || (!is_local_in_initial_view))
    {
        gcry_sexp_release(trusted_key);
        trusted_key = NULL;
    }

    /* Init the log handler */
    log_file = fopen(argv[6], "a");
    if (log_file == NULL)
    {
        fprintf(stderr, "Could not open the log file '%s'", argv[6]);
        fflush(stderr);
        gcry_sexp_release(private_trusted_key);
        gcry_sexp_release(trusted_key);
        g_slist_free(corrects);
        g_slist_free(init_view);
        g_slist_free(init_keys);
        g_slist_free_full(scenario, (void (*)(void *)) free_scenario_block);
        g_slist_free_full(clients, free);
        g_slist_free_full(processes, free);
        g_slist_free_full(public_keys, (void (*)(void *)) gcry_sexp_release);
        exit(1);
    }
    g_log_set_handler("GPDGC",
            G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION,
            main_log_handler, NULL);

    /* Init the client/server */
    unsigned short max_pending_replies = 20;
    unsigned int network_buffer_size = 262144;
    struct sockaddr *self = (struct sockaddr *) self_address;
    gcry_sexp_t self_private_key = load_keys ? read_key(argv[2]) : NULL;
    if (is_local_client)
    {
        gcry_sexp_t self_public_key = load_keys ? read_key(argv[3]) : NULL;
        client = gpdgc_create_client(process_model, channel_model, validation,
                self, self_private_key, self_public_key, 7, 5,
                max_pending_replies, MESSAGE_SIZE, network_buffer_size,
                tick_length, 50, callback_deliver, callback_inform);
        server = NULL;

        if ((client != NULL)
                && (!gpdgc_subscribe_to_view(client, init_view, init_keys)))
        {
            fprintf(stderr, "Unable to init the client view !\n");
            fflush(stderr);
            gpdgc_close_client(client); 
            client = NULL;
        }
    }
    else
    {
        client = NULL;
        server = gpdgc_create_server(process_model, channel_model, validation,
                election, self, self_private_key, NULL, 7, 10, 10, 5*1000*1000,
                0, 10, 20, MESSAGE_SIZE, network_buffer_size, tick_length, 5,
                100, 5, 50, 5, 1, callback_adeliver, callback_rdeliver,
                callback_inform);
        if ((server != NULL) 
                && (is_local_in_initial_view
                    ? (!gpdgc_init_view(server, init_view, 
                            init_keys, trusted_key))
                    : (!gpdgc_integrate_view(server, init_view))))
        {
            fprintf(stderr, "Unable to init the server view !\n");
            fflush(stderr);
            gpdgc_close_server(server); 
            gcry_sexp_release(trusted_key);
            trusted_key = NULL;
            server = NULL;
        }
    }
    g_slist_free(init_view);
    if (is_local_client || ((server != NULL) && is_local_in_initial_view))
    {
        g_slist_free(init_keys);
    }
    else
    {
        g_slist_free_full(init_keys, (void (*)(void *)) gcry_sexp_release);
    }

    if ((is_local_client && (client == NULL))
            || ((!is_local_client) && (server == NULL)))
    {
        fprintf(stderr, "Unable to build the client/server !\n");
        fflush(stderr);
        fclose(log_file);
        gcry_sexp_release(trusted_key);
        gcry_sexp_release(private_trusted_key);
        g_slist_free(corrects);
        g_slist_free_full(scenario, (void (*)(void *)) free_scenario_block);
        g_slist_free_full(clients, free);
        g_slist_free_full(processes, free);
        g_slist_free_full(public_keys, (void (*)(void *)) gcry_sexp_release);
        exit(1);
    }

    /* Execute the scenario */ 
    char *label = get_address_label(self_address);
    unsigned int message_counter = 0;
    GSList *block_iterator = scenario;
    while ((block_iterator != NULL) && (!excluded))
    {
        scenario_block *block = (scenario_block *) block_iterator->data;
        block_iterator = block_iterator->next;

        unsigned int nb_abcast_sent = 0;
        unsigned int nb_rbcast_sent = 0;
        while ((!excluded)
                && ((nb_abcast_sent < block->nb_abcast)
                    || (nb_rbcast_sent < block->nb_rbcast)))
        {
            char *msg = malloc(MESSAGE_SIZE * sizeof(char));
            for (int i=0; i<MESSAGE_SIZE; i++)
            {
                msg[i]='\0';
            }
            sprintf(msg, "MESSAGE %s:%05d", label, message_counter);
            message_counter++;

            unsigned long last_rid = 0;
            unsigned int rbcast =
                (rand() % 2 || (nb_abcast_sent >= block->nb_abcast))
                && (nb_rbcast_sent < block->nb_rbcast);
            if (rbcast)
            {
                if (server != NULL)
                {
                    gpdgc_reliable_broadcast(server, msg, MESSAGE_SIZE);
                }
                else if (client != NULL)
                {
                    unsigned long *rid = malloc(sizeof(unsigned long));
                    gpdgc_reliable_multicast(client, msg, MESSAGE_SIZE, rid);

                    replies = g_slist_append(replies, rid);
                    last_rid = *rid;
                }
                nb_rbcast_sent++;
            }
            else
            {
                if (server != NULL)
                {
                    gpdgc_atomic_broadcast(server, msg, MESSAGE_SIZE);
                }
                else if (client != NULL)
                {
                    unsigned long *rid = malloc(sizeof(unsigned long));
                    gpdgc_atomic_multicast(client, msg, MESSAGE_SIZE, rid);

                    replies = g_slist_append(replies, rid);
                    last_rid = *rid;
                }
                nb_abcast_sent++;
            }
            free(msg);
            
            if (client != NULL)
            {
                unsigned short highest_rid = last_rid 
                    + g_slist_length(block->add_processes)
                    + g_slist_length(block->remove_processes)
                    + g_slist_length(block->update_keys);

                while (!check_pending_replies(highest_rid, max_pending_replies))
                {
                    g_usleep(100 * 1000);
                }
            }
        }

        if (client != NULL)
        {
            GSList *add_iterator = block->add_processes;
            while ((!excluded) && (add_iterator != NULL))
            {
                struct sockaddr *add_process = add_iterator->data;
                add_iterator = add_iterator->next;
                gcry_sexp_t add_key =
                    retrieve_public_key((struct sockaddr_in *)add_process,
                            processes, public_keys); 

                if (!gpdgc_add_to_view(client,
                            add_process, add_key, private_trusted_key))
                {
                    fprintf(stderr, "Cannot init process addition !\n");
                }
            }

            GSList *remove_iterator = block->remove_processes;
            while ((!excluded) && (remove_iterator != NULL))
            {
                struct sockaddr *remove_process = remove_iterator->data;
                remove_iterator = remove_iterator->next;

                if (!gpdgc_remove_from_view(client,
                            remove_process, private_trusted_key))
                {
                    fprintf(stderr, "Cannot init process removal !\n");
                }
            }

            GSList *update_iterator = block->update_keys;
            while ((!excluded) && (update_iterator != NULL))
            {
                gcry_sexp_t update_key = update_iterator->data;
                update_iterator = update_iterator->next;

                if (!gpdgc_update_trusted_key(client,
                            update_key, private_trusted_key))
                {
                    fprintf(stderr, "Cannot init key update !\n");
                }
            }
        }

        if (block->break_duration > 0)
        {
            gulong break_period = 1000 * block->break_duration; 
            g_usleep(break_period);
        }

        if ((server != NULL) && block->crash)
        {
            printf("Server crashes !\n");
            fflush(stdout);
            gpdgc_close_server(server); 
            fclose(log_file);
            gcry_sexp_release(private_trusted_key);
            g_slist_free(corrects);
            g_slist_free_full(scenario, (void (*)(void *)) free_scenario_block);
            g_slist_free_full(clients, free);
            g_slist_free_full(processes, free);
            g_slist_free_full(public_keys, (void (*)(void *)) gcry_sexp_release);
            exit(0);
        }
    }
    free(label);

    /* Wait that client/server can be locally closed */
    if ((server != NULL) && (!is_local_faulty) && (!excluded))
    {
        printf("Wait unsubscription from clients !\n");
        fflush(stdout);
        while (!deserved_all_clients(server))
        {
            g_usleep(100*1000);
        }

        printf("Send ending message and wait for all ending messages !\n");
        fflush(stdout);

        gpdgc_atomic_broadcast(server, LAST_MESSAGE, MESSAGE_SIZE);
        while (!received_all_messages(terminated, corrects, server))
        {
            g_usleep(100*1000);
        }
    }
    else if (client != NULL)
    {
        printf("Wait all expected replies have been received !\n");
        fflush(stdout);
        while (g_slist_length(replies) != 0)
        {
            g_usleep(100 * 1000);
        }

        printf("Unsubscribe from servers !\n");
        fflush(stdout);
        gpdgc_unsubscribe_from_view(client);
    }
    else if (!excluded)
    {
        printf("Wait until no more messages is received !\n");
        fflush(stdout);

        unsigned short previous_nb_received_messages = 0;
        while (nb_received_messages > previous_nb_received_messages)
        {
            previous_nb_received_messages = nb_received_messages;
            g_usleep(15 * 1000 * 1000);
        }
    }

    /* Close the server after 15 seconds */
    g_usleep(15 * 1000 * 1000);
    printf("Close program\n\n");
    fflush(stdout);
    if (client != NULL)
    {
        gpdgc_close_client(client);
    }
    if (server != NULL)
    {
        gpdgc_close_server(server); 
    }
    fclose(log_file);
    gcry_sexp_release(private_trusted_key);
    g_slist_free(corrects);
    g_slist_free_full(replies, free);
    g_slist_free_full(scenario, (void (*)(void *)) free_scenario_block);
    g_slist_free_full(clients, free);
    g_slist_free_full(processes, free);
    g_slist_free_full(public_keys, (void (*)(void *)) gcry_sexp_release);
    return 0;
}
