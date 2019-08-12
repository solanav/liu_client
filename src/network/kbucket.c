#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "kbucket.h"
#include "netcore.h"
#include "types.h"

int copy_kpeer(kpeer *dst, const kpeer *src);

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
    if (as == NULL)
    {
        DEBUG_PRINT(P_ERROR "Address space is NULL\n");
        return;
    }

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

int id_between(const byte start[PEER_ID_LEN], const byte end[PEER_ID_LEN], const byte id[PEER_ID_LEN])
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
    if (as == NULL)
    {
        DEBUG_PRINT(P_ERROR "Address space is NULL\n");
        return ERROR;
    }

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

    // Keep count of kbuckets
    as->num++;

    // Reorder peers after adding new kbucket
    reorder_kpeer(as);

    return OK;
}

int get_kb(addr_space *as, const byte id[PEER_ID_LEN])
{
    if (as == NULL)
    {
        DEBUG_PRINT(P_ERROR "Address space is NULL\n");
        return ERROR;
    }

    // Iterate through all kbuckets
    for (unsigned int i = 0; i < as->num; i++)
    {
        if (id_between(as->kb_list[i]->start, as->kb_list[i]->end, id) == OK)
            return i;
    }

    return ERROR;
}

void print_id(const byte id[PEER_ID_LEN])
{
    printf("[ ");
    for (int i = 0; i < PEER_ID_LEN; i += 4)
        printf("%02x%02x%02x%02x ", id[i], id[i + 1], id[i + 2], id[i + 3]);
    printf("]");
}

void print_kp(const kpeer *peer)
{
    if (peer == NULL)
    {
        DEBUG_PRINT(P_ERROR "Peer you are printing is null\n");
        return;
    }

    char ip[INET_ADDRSTRLEN];
    ip_string(peer->ip, ip);

    printf("[%16s:%-5d]", ip, peer->port);
    print_id(peer->id);
}

void print_kb(const kbucket *kb)
{
    if (kb == NULL)
    {
        DEBUG_PRINT(P_ERROR "Kbucket space is NULL\n");
        return;
    }

    for (int i = 0; i < MAX_KPEERS; i++)
    {
        printf("\t[%d] ", kb->free[i]);
        print_kp(&(kb->peer[i]));
        printf("\n");
    }
}

void print_as(const addr_space *as)
{
    if (as == NULL)
    {
        DEBUG_PRINT(P_ERROR "Address space is NULL\n");
        return;
    }

    for (unsigned int i = 0; i < as->num; i++)
    {
        printf("(%d) KBUCKET \n", i);

        print_id(as->kb_list[i]->start);
        printf("\n");
        print_id(as->kb_list[i]->end);
        printf("\n");

        print_kb(as->kb_list[i]);
    }
}

int reorder_kpeer(addr_space *as)
{
    if (as == NULL)
    {
        DEBUG_PRINT(P_ERROR "Address space is NULL\n");
        return ERROR;
    }

    for (unsigned int i = 0; i < as->num; i++)
    {
        for (unsigned int j = 0; j < MAX_KPEERS; j++)
        {
            if (as->kb_list[i]->free[j] == 1)
            {
                kpeer peer;
                peer.ip = as->KPEER(i, j).ip;
                peer.port = as->KPEER(i, j).port;
                memcpy(peer.id, as->KPEER(i, j).id, PEER_ID_LEN);

                as->kb_list[i]->free[j] = 0;
                as->kb_list[i]->peer[j].port = 0;
                as->kb_list[i]->peer[j].ip = 0;
                memset(as->kb_list[i]->peer[j].id, 0, PEER_ID_LEN);

                add_kpeer(as, &peer);
            }
        }
    }

    return OK;
}

int add_kpeer(addr_space *as, const kpeer *peer)
{
    if (as == NULL)
    {
        DEBUG_PRINT(P_ERROR "Address space is NULL\n");
        return ERROR;
    }

    int kb_i = -1;
    int peer_i = -1;
    do
    {
        // Get bucket in which this peer should go
        kb_i = get_kb(as, peer->id);
        if (kb_i == ERROR)
        {
            DEBUG_PRINT(P_ERROR "Failed to get a kbucket\n");
            return ERROR;
        }

        // Look for empty space in bucket
        for (int i = 0; i < MAX_KPEERS && peer_i == -1; i++)
        {
            if (as->kb_list[kb_i]->free[i] == 0)
                peer_i = i;
        }

        // If no space
        if (peer_i == -1)
        {
            DEBUG_PRINT(P_INFO "Failed to find space in kbucket %d\n", kb_i);

            // Only create new kbucket if we fit in the last
            if ((unsigned int) kb_i == as->num - 1)
            {
                if (add_kb(as) == ERROR)
                {
                    DEBUG_PRINT(P_ERROR "Failed to create new bucket\n");
                    return ERROR;
                }
            }
            else
            {
                DEBUG_PRINT(P_INFO "Peer does not fit in any kbucket\n");
                return ERROR;
            }
        }
    } while (peer_i == -1);

    // Copy data to kbucket's free space
    as->KPEER(kb_i, peer_i).ip = peer->ip;
    as->KPEER(kb_i, peer_i).port = peer->port;
    memcpy(as->KPEER(kb_i, peer_i).id, peer->id, PEER_ID_LEN);
    as->kb_list[kb_i]->free[peer_i] = 1;

    return OK;
}

int get_kpeer(addr_space *as, in_addr_t ip, kpeer *peer)
{
    if (as == NULL)
    {
        DEBUG_PRINT(P_ERROR "Address space is NULL\n");
        return ERROR;
    }

    for (unsigned int i = 0; i < as->num; i++)
    {
        for (int j = 0; j < MAX_KPEERS; j++)
        {
            if (as->KPEER(i, j).ip == ip)
            {
                peer->ip = as->KPEER(i, j).ip;
                peer->port = as->KPEER(i, j).port;
                memcpy(peer->id, as->KPEER(i, j).id, PEER_ID_LEN);

                return OK;
            }
        }
    }

    return ERROR;
}

int create_kpeer(kpeer *dst, const in_addr_t ip, const in_port_t port, const byte id[PEER_ID_LEN])
{
    if (dst == NULL)
    {
        DEBUG_PRINT(P_ERROR "Destiny is NULL\n");
        return ERROR;
    }

    dst->ip = ip;
    dst->port = port;
    memcpy(dst->id, id, PEER_ID_LEN);

    return OK;
}

int copy_kpeer(kpeer *dst, const kpeer *src)
{
    if (dst == NULL)
    {
        DEBUG_PRINT(P_ERROR "Destiny is NULL\n");
        return ERROR;
    }

    dst->ip = src->ip;
    dst->port = src->port;
    memcpy(dst->id, src->id, PEER_ID_LEN);

    return OK;
}
