#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "kpeer.h"
#include "netcore.h"
#include "types.h"

int copy_kpeer(kpeer *dst, const kpeer *src);

void init_as(addr_space *as)
{
    memset(as->kb_list, 0, MAX_KBUCKETS * sizeof(kbucket));
    as->b_num = 1;
    as->p_num = 0;

    // Set first kbucket's variables
    memset(as->kb_list[0].start, 0x00, PEER_ID_LEN);
    memset(as->kb_list[0].end, 0xFF, PEER_ID_LEN);
    as->free[0] = 1;
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
    if (memcmp(id, start, PEER_ID_LEN) < 0)
        return ERROR;

    // Check end is bigger
    if (memcmp(id, end, PEER_ID_LEN) > 0)
        return ERROR;

    return OK;
}

int add_kb(addr_space *as)
{
    if (as == NULL)
    {
        DEBUG_PRINT(P_ERROR "Address space is NULL\n");
        return ERROR;
    }

    if (as->b_num == MAX_KBUCKETS)
    {
        DEBUG_PRINT(P_ERROR "Cannot create more kbuckets\n");
        return ERROR;
    }

    // Old kbucket's end to new kbucket's end
    memcpy(as->kb_list[as->b_num].end, as->kb_list[as->b_num - 1].end, PEER_ID_LEN);

    // Half is now the end of old kbucket
    byte space[PEER_ID_LEN];
    diff_id(space, as->kb_list[as->b_num - 1].end, as->kb_list[as->b_num - 1].start);
    half_id(space);
    add_id(space, space, as->kb_list[as->b_num - 1].start);
    memcpy(as->kb_list[as->b_num - 1].end, space, PEER_ID_LEN);

    // Half + 1 is now the start of new kbucket
    inc_id(space);
    memcpy(as->kb_list[as->b_num].start, space, PEER_ID_LEN);

    // Keep count of kbuckets
    as->b_num++;

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
    for (unsigned int i = 0; i < as->b_num; i++)
    {
        if (id_between(as->kb_list[i].start, as->kb_list[i].end, id) == OK)
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

    printf("PEER NUMBER: %d\n", as->p_num);

    for (unsigned int i = 0; i < as->b_num; i++)
    {
        printf("(%d) KBUCKET \n", i);

        print_id(as->kb_list[i].start);
        printf("\n");

        print_kb(&(as->kb_list[i]));

        print_id(as->kb_list[i].end);
        printf("\n");
    }
}

int reorder_kpeer(addr_space *as)
{
    if (as == NULL)
    {
        DEBUG_PRINT(P_ERROR "Address space is NULL\n");
        return ERROR;
    }

    for (unsigned int i = 0; i < as->b_num; i++)
    {
        for (unsigned int j = 0; j < MAX_KPEERS; j++)
        {
            if (as->kb_list[i].free[j] != 0)
            {
                // Create copy of peer
                kpeer peer;
                copy_kpeer(&peer, &(as->_KPEER(i, j)));

                // Save the free status
                int tmp;
                if (as->kb_list[i].free[j] == 2)
                    tmp = 1;
                else
                    tmp = 0;

                rm_kpeer(as, peer.ip);

                // Re-add the peer
                add_kpeer(as, &peer, tmp);
            }
        }
    }

    return OK;
}

int add_kpeer(addr_space *as, const kpeer *peer, unsigned int self)
{
    if (as == NULL)
    {
        DEBUG_PRINT(P_ERROR "Address space is NULL\n");
        return ERROR;
    }

    // Check peer is not saved already
    if (get_kpeer(as, peer->ip, NULL) == OK)
    {
        DEBUG_PRINT(P_WARN "Peer already added\n");
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
            if (as->kb_list[kb_i].free[i] == 0)
                peer_i = i;
        }

        // If no space
        if (peer_i == -1)
        {
            DEBUG_PRINT(P_INFO "Failed to find space in kbucket %d\n", kb_i);

            // Find self peer
            int self_bucket = -1;
            for (int i = 0; i < MAX_KBUCKETS; i++)
            {
                for (int j = 0; j < MAX_KBUCKETS; j++)
                {
                    if (as->kb_list[i].free[j] == 2)
                        self_bucket = i;
                }
            }

            if (self_bucket == -1)
            {
                DEBUG_PRINT(P_ERROR "Failed to find self in the buckets, could not add new bucket\n");
                return ERROR;
            }

            // Only create new kbucket if it corresponds to the same we are in
            if (kb_i == self_bucket)
            {
                if (add_kb(as) == ERROR)
                {
                    DEBUG_PRINT(P_ERROR "Failed to create new bucket\n");
                    return ERROR;
                }
                else
                {
                    DEBUG_PRINT(P_OK "Created new k-bucket, copying peer to new one\n");
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
    copy_kpeer(&(as->_KPEER(kb_i, peer_i)), peer);
    if (self == 1)
    {
        DEBUG_PRINT(P_INFO "Added self peer\n");
        as->kb_list[kb_i].free[peer_i] = 2;
    }
    else
    {
        DEBUG_PRINT(P_INFO "Added other peer\n");
        as->kb_list[kb_i].free[peer_i] = 1;
    }

    as->p_num++;

    return OK;
}

int get_kpeer(const addr_space *as, const in_addr_t ip, k_index *ki)
{
    if (as == NULL)
    {
        DEBUG_PRINT(P_ERROR "Address space is NULL\n");
        return ERROR;
    }

    for (unsigned int i = 0; i < as->b_num; i++)
    {
        for (int j = 0; j < MAX_KPEERS; j++)
        {
            if (as->_KPEER(i, j).ip == ip)
            {
                if (ki)
                {
                    ki->b = i;
                    ki->p = j;
                }

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

    if (id != NULL)
        memcpy(dst->id, id, PEER_ID_LEN);

    dst->secure = DTLS_NO;
    memset(&(dst->key), 0, sizeof(dst->key));
    memset(&(dst->latency), 0, sizeof(dst->key));

    return OK;
}

int rm_kpeer(addr_space *as, const in_addr_t ip)
{
    // Find the peer
    k_index ki;
    if (get_kpeer(as, ip, &ki) == ERROR)
        return ERROR;

    // Set peer to zero and free to true (0)
    memset(&(as->_KPEER(ki.b, ki.p)), 0, sizeof(kpeer));
    as->kb_list[ki.b].free[ki.p] = 0;

    // Update structure
    as->p_num--;

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

int export_bin(addr_space *as)
{
    int bin = open("bootstrap.bin", O_WRONLY, O_CREAT);

    for (int i = 0; i < MAX_KBUCKETS; i++)
    {
        for (int j = 0; j < MAX_KPEERS; j++)
        {
            write(bin, &(as->_KPEER(i, j).ip), sizeof(in_addr_t));
            write(bin, &(as->_KPEER(i, j).port), sizeof(in_port_t));
            write(bin, as->_KPEER(i,j).id, PEER_ID_LEN);
            write(bin, &(as->kb_list[i].free[j]), sizeof(unsigned short));
        }
    }

    return OK;
}

int import_bin(addr_space *as)
{
    int bin = open("bootstrap.bin", O_RDONLY);

    for (int i = 0; i < MAX_KBUCKETS; i++)
    {
        for (int j = 0; j < MAX_KPEERS; j++)
        {
            in_addr_t tmp_ip;
            in_port_t tmp_port;
            unsigned short free;
            byte tmp_id[PEER_ID_LEN];

            read(bin, &tmp_ip, sizeof(in_addr_t));
            char tmp_ip_string[INET_ADDRSTRLEN];
            ip_string(tmp_ip, tmp_ip_string);
            printf("IP>%s\n", tmp_ip_string);
            read(bin, &tmp_port, sizeof(in_port_t));
            printf("PT>%d\n", tmp_port);
            read(bin, tmp_id, PEER_ID_LEN);
            printf("ID>");
            print_id(tmp_id);
            read(bin, &free, sizeof(unsigned short));
            printf("\nFR>%u\n", free);

            if (free != 0)
            {
                kpeer tmp;
                create_kpeer(&tmp, tmp_ip, tmp_port, tmp_id);
                add_kpeer(as, &tmp, 0);
            }
        }
    }

    return OK;
}

void distance(byte result[PEER_ID_LEN], const byte id1[PEER_ID_LEN], const byte id2[PEER_ID_LEN])
{
    for (int i = 0; i < PEER_ID_LEN; i++)
    {
        result[i] = id1[i] ^ id2[i];
    }
}

int distance_peer_list(byte list[C_UDP_LEN], const byte id[INET_ADDRSTRLEN], addr_space *as)
{
    size_t triple_size = sizeof(in_addr_t) + sizeof(in_port_t) + PEER_ID_LEN;

    for (int offset = 0; as->p_num > 0; offset++)
    {
        int first = 0;
        byte xor_metric[PEER_ID_LEN] = {-1};
        kpeer closest;

        // Find closest peer
        for (int i = 0; i < MAX_KBUCKETS; i++)
        {
            for (int j = 0; j < MAX_KPEERS; j++)
            {
                // If empty, skip
                if (as->kb_list[i].free[j] == 0)
                    continue;

                byte current_xor[PEER_ID_LEN];
                distance(current_xor, as->_KPEER(i, j).id, id);

                // If first peer, copy to closest
                if (first == 0)
                {
                    first = 1;
                    memcpy(xor_metric, current_xor, PEER_ID_LEN);
                    memcpy(&closest, &(as->_KPEER(i, j)), sizeof(kpeer));
                }
                else if (memcmp(current_xor, xor_metric, PEER_ID_LEN) < 0)
                {
                    memcpy(xor_metric, current_xor, PEER_ID_LEN);
                    memcpy(&closest, &(as->_KPEER(i, j)), sizeof(kpeer));
                }
            }
        }

        // Copy ip
        (list + (offset * triple_size))[0] = closest.ip >> 24;
        (list + (offset * triple_size))[1] = (closest.ip >> 16) & 0xFF;
        (list + (offset * triple_size))[2] = (closest.ip >> 8) & 0xFF;
        (list + (offset * triple_size))[3] = closest.ip & 0xFF;

        // Copy port
        (list + (offset * triple_size))[4] = closest.port >> 8;
        (list + (offset * triple_size))[5] = closest.port & 0xFF;

        // Copy id
        memcpy(list + (offset * triple_size) + 6, closest.id, PEER_ID_LEN);

        // Remove the peer
        rm_kpeer(as, closest.ip);
    }

    return OK;
}
