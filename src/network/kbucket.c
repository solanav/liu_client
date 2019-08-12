#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "kbucket.h"
#include "netcore.h"
#include "types.h"

addr_space *init_kb()
{
    addr_space *as = calloc(1, sizeof(addr_space));

    as->kb_list = calloc(1, sizeof(kbucket *));
    if (as->kb_list == NULL)
    {
        DEBUG_PRINT(P_ERROR "Calloc failed when adding kbucket to list\n");
        return NULL;
    }

    as->kb_list[0] = calloc(1, sizeof(kbucket));
    if (as->kb_list[0] == NULL)
    {
        DEBUG_PRINT(P_ERROR "Calloc failed when adding kbucket to list\n");
        return NULL;
    }

    as->num = 1;

    memset(as->kb_list[0], 0, sizeof(kbucket));
    memset(as->kb_list[0]->end, '\xFF', PEER_ID_LEN);

    return as;
}

void clean_kb(addr_space *as)
{
    for (unsigned int i = 0; i < as->num; i++)
        free(as->kb_list[i]);

    free(as->kb_list);
    free(as);
}

int half_id(byte id[PEER_ID_LEN])
{
    for (int i = 0; i < PEER_ID_LEN; i++)
    {
        if (id[i] != 0)
        {
            id[i] /= 2;
            return OK;
        }
    }

    return ERROR;
}

int add_id(byte total[PEER_ID_LEN], const byte id1[PEER_ID_LEN], const byte id2[PEER_ID_LEN])
{
    byte idc[PEER_ID_LEN];
    memcpy(idc, id2, PEER_ID_LEN);
    memcpy(total, id1, PEER_ID_LEN);

    int carry = 0;
    for (int i = PEER_ID_LEN - 1; i >= 0; i--)
    {

        //printf("[%02x] + [%02x] = ", total[i], idc[i]);

        int ot = total[i];
        total[i] = idc[i] + total[i];

        if (total[i] < idc[i] || total[i] < ot)
        {
            total[i] += carry;
            carry = 1;
        }
        else
        {
            total[i] += carry;
            carry = 0;
        }

        //printf("[%02x] (%d)\n", total[i], carry);
    }

    return OK;
}

int diff_id(byte diff[PEER_ID_LEN], const byte id1[PEER_ID_LEN], const byte id2[PEER_ID_LEN])
{
    byte idc[PEER_ID_LEN];
    memcpy(idc, id2, PEER_ID_LEN);
    memcpy(diff, id1, PEER_ID_LEN);

    int carry = 0;
    for (int i = PEER_ID_LEN - 1; i >= 0; i--)
    {
        if (carry == 1)
        {
            idc[i]++;
            if (idc[i] != 0)
                carry = 0;
        }

        if (diff[i] < idc[i])
        {
            carry = 1;
            diff[i] = idc[i] - diff[i];
        }
        else
            diff[i] = diff[i] - idc[i];
    }

    return OK;
}

int inc_id(byte id[PEER_ID_LEN])
{
    for (int i = PEER_ID_LEN - 1; i >= 0; i--)
    {
        id[i]++;
        if (id[i] != 0)
            return OK;
    }

    return ERROR;
}

int id_between(byte start[PEER_ID_LEN], byte end[PEER_ID_LEN], byte id[PEER_ID_LEN])
{
    // Check start is smaller
    for (int i = 0; i < PEER_ID_LEN; i++)
    {
        if (start[i] > id[i])
            return ERROR;
        else if (start[i] < id[i])
            break;
    }

    // Check end is bigger
    for (int i = 0; i < PEER_ID_LEN; i++)
    {
        if (end[i] < id[i])
            return ERROR;
        else if (end[i] > id[i])
            break;
    }

    return OK;
}

int add_kb(addr_space *as)
{
    as->kb_list = realloc(as->kb_list, (as->num + 1) * sizeof(kbucket *));
    if (as->kb_list == NULL)
    {
        DEBUG_PRINT(P_ERROR "Realloc failed when creating space for kbucket\n");
        return ERROR;
    }

    DEBUG_PRINT(P_INFO "Now space for %d kbuckets\n", (as->num + 1));

    as->kb_list[as->num] = calloc(1, sizeof(kbucket));
    if (as->kb_list[as->num] == NULL)
    {
        DEBUG_PRINT(P_ERROR "Calloc failed when adding kbucket to list\n");
        return ERROR;
    }

    // Old kbucket's end to new kbucket's end
    memcpy(as->kb_list[as->num]->end, as->kb_list[as->num - 1]->end, PEER_ID_LEN);

    // Half is now the end of old kbucket
    byte space[PEER_ID_LEN];
    diff_id(space, as->kb_list[as->num - 1]->end, as->kb_list[as->num - 1]->start);
    half_id(space);
    add_id(space, space, as->kb_list[as->num - 1]->start);
    memcpy(as->kb_list[as->num - 1]->end, space, PEER_ID_LEN);

    // Half + 1 is now the start of new kbucket
    inc_id(space);
    memcpy(as->kb_list[as->num]->start, space, PEER_ID_LEN);

    as->num++;

    // Reorder peers after adding new kbucket
    reorder_kpeer(as);

    return OK;
}

int get_kb(addr_space *as, byte id[PEER_ID_LEN])
{
    // Iterate through all kbuckets
    for (unsigned int i = 0; i < as->num; i++)
    {
        if (id_between(as->kb_list[i]->start, as->kb_list[i]->end, id) == OK)
            return i;
    }

    return ERROR;
}

void print_kb(kbucket *kb, char c)
{

    for (int i = 0; i < MAX_KPEERS; i++)
    {
        char ip[INET_ADDRSTRLEN];
        ip_string(kb->ip[i], ip);

        printf("%c[%d] [%16s:%-5d] ", c, kb->free[i], ip, kb->port[i]);
        print_id(kb->id[i]);
        printf("\n");
    }
}

void print_as(addr_space *as)
{
    for (unsigned int i = 0; i < as->num; i++)
    {
        printf("(%d) KBUCKET \n", i);

        print_id(as->kb_list[i]->start);
        printf("\n");
        print_id(as->kb_list[i]->end);
        printf("\n");

        print_kb(as->kb_list[i], '\t');
    }
}

void print_id(byte id[PEER_ID_LEN])
{
    printf("[ ");
    for (int i = 0; i < PEER_ID_LEN; i += 4)
        printf("%02x%02x%02x%02x ", id[i], id[i + 1], id[i + 2], id[i + 3]);
    printf("]");
}

int reorder_kpeer(addr_space *as)
{
    for (unsigned int i = 0; i < as->num; i++)
    {
        for (unsigned int j = 0; j < MAX_KPEERS; j++)
        {
            if (as->kb_list[i]->free[j] == 1)
            {
                byte id[PEER_ID_LEN];
                unsigned int port = as->kb_list[i]->port[j];
                in_addr_t ip = as->kb_list[i]->ip[j];
                memcpy(id, as->kb_list[i]->id[j], PEER_ID_LEN);

                as->kb_list[i]->free[j] = 0;
                as->kb_list[i]->port[j] = 0;
                as->kb_list[i]->ip[j] = 0;
                memset(as->kb_list[i]->id[j], 0, PEER_ID_LEN);

                add_kpeer(as, ip, port, id);
            }
        }
    }

    return OK;
}

int add_kpeer(addr_space *as, in_addr_t ip, in_port_t port, byte id[PEER_ID_LEN])
{
    int kb_index = get_kb(as, id);
    if (kb_index == ERROR)
    {
        DEBUG_PRINT(P_ERROR "Failed to get a kbucket\n");
        return ERROR;
    }

    int peer_index = -1;
    for (int i = 0; i < MAX_KPEERS && peer_index == -1; i++)
    {
        if (as->kb_list[kb_index]->free[i] == 0)
            peer_index = i;
    }

    if (peer_index == -1)
    {
        DEBUG_PRINT(P_INFO "Failed to find space in kbucket %d\n", kb_index);
        
        add_kb(as);

        kb_index = get_kb(as, id);
        if (kb_index == ERROR)
        {
            DEBUG_PRINT(P_ERROR "Failed to get a kbucket\n");
            return ERROR;
        }

        peer_index = -1;
        for (int i = 0; i < MAX_KPEERS && peer_index == -1; i++)
        {
            if (as->kb_list[kb_index]->free[i] == 0)
                peer_index = i;
        }

        if (peer_index == -1)
        {
            DEBUG_PRINT(P_INFO "Failed to find space in kbucket %d\n", kb_index);
            return ERROR;
        }
    }

    // Copy data to kbucket's free space
    as->kb_list[kb_index]->ip[peer_index] = ip;
    memcpy(as->kb_list[kb_index]->id[peer_index], id, PEER_ID_LEN);
    as->kb_list[kb_index]->port[peer_index] = port;
    as->kb_list[kb_index]->free[peer_index] = 1;

    return OK;
}