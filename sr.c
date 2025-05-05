#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include "emulator.h"
#include "sr.h"

/* ******************************************************************
   Selective-Repeat Protocol with debug checks
**********************************************************************/

#define RTT 16.0      /* round trip time. MUST BE SET TO 16.0 when submitting */
#define WINDOWSIZE 6  /* maximum number of buffered unacked packets */
#define SEQSPACE 7    /* sequence space must be >= WINDOWSIZE + 1 */
#define NOTINUSE (-1) /* header field not in use */

/* Emulator counters (defined in emulator.c) */
extern int total_ACKs_received;
extern int new_ACKs;
extern int packets_resent;
extern int packets_received;
extern int window_full;

/* Compute checksum over header + payload */
int ComputeChecksum(struct pkt packet)
{
    int checksum = packet.seqnum + packet.acknum;
    int i;
    for (i = 0; i < 20; i++)
    {
        checksum += (int)packet.payload[i];
    }
    return checksum;
}

/* Check for corruption */
bool IsCorrupted(struct pkt packet)
{
    return (packet.checksum != ComputeChecksum(packet));
}

/* Sender (A) state */
static struct pkt buffer[SEQSPACE]; /* buffer packets by seqnum */
static bool acked[SEQSPACE];
static int send_base;
static int next_seqnum;

/* check if x is in the send window */
static bool in_send_window(int x)
{
    int dist = (x - send_base + SEQSPACE) % SEQSPACE;
    return (dist < WINDOWSIZE);
}

void A_init(void)
{
    int i;
    send_base = 0;
    next_seqnum = 0;
    for (i = 0; i < SEQSPACE; i++)
    {
        acked[i] = false;
    }
}

void A_output(struct msg message)
{
    int i;
    struct pkt p;

    /* sanity checks */
    assert(send_base >= 0 && send_base < SEQSPACE);
    assert(next_seqnum >= 0 && next_seqnum < SEQSPACE);

    /* debug info */
    if (TRACE > 1)
    {
        printf("[DBG] A_output: send_base=%d next_seqnum=%d\n", send_base, next_seqnum);
    }

    if (!in_send_window(next_seqnum))
    {
        window_full++;
        if (TRACE > 0)
            printf("----A: Window full, dropping message\n");
        return;
    }

    /* build packet */
    p.seqnum = next_seqnum;
    p.acknum = NOTINUSE;
    for (i = 0; i < 20; i++)
    {
        p.payload[i] = message.data[i];
    }
    p.checksum = ComputeChecksum(p);

    /* buffer before send */
    buffer[next_seqnum] = p;

    /* trace & send */
    if (TRACE > 0)
        printf("----A: New message arrives, send window is not full, send new messge to layer3!\n");
    printf("Sending packet %d to layer 3\n", p.seqnum);
    tolayer3(A, p);

    /* start timer if base */
    if (send_base == next_seqnum)
    {
        starttimer(A, RTT);
    }

    next_seqnum = (next_seqnum + 1) % SEQSPACE;
}

void A_input(struct pkt packet)
{
    int ack = packet.acknum;

    /* sanity checks */
    assert(send_base >= 0 && send_base < SEQSPACE);
    assert(next_seqnum >= 0 && next_seqnum < SEQSPACE);

    /* debug info */
    printf("[DBG] A_input: recv ACK=%d send_base=%d next_seqnum=%d\n",
           ack, send_base, next_seqnum);
    if (ack < 0 || ack >= SEQSPACE)
    {
        printf("[ERR] A_input: bogus ACK %d\n", ack);
        return;
    }

    if (IsCorrupted(packet))
    {
        if (TRACE > 0)
            printf("----A: Corrupted ACK, ignoring\n");
        return;
    }

    if (in_send_window(ack) && !acked[ack])
    {
        total_ACKs_received++;
        new_ACKs++;
        acked[ack] = true;
        if (TRACE > 0)
            printf("----A: uncorrupted ACK %d is received\n", ack);
        if (TRACE > 0)
            printf("----A: ACK %d is not a duplicate\n", ack);

        /* slide window */
        while (acked[send_base])
        {
            acked[send_base] = false;
            send_base = (send_base + 1) % SEQSPACE;
        }

        /* timer control */
        stoptimer(A);
        if (send_base != next_seqnum)
            starttimer(A, RTT);
    }
    else
    {
        if (TRACE > 0)
            printf("----A: ACK %d is a duplicate or out-of-window, ignoring\n", ack);
    }
}

void A_timerinterrupt(void)
{
    /* sanity check */
    assert(send_base >= 0 && send_base < SEQSPACE);

    if (TRACE > 0)
        printf("----A: Timeout, resending packet %d\n", send_base);
    tolayer3(A, buffer[send_base]);
    packets_resent++;
    starttimer(A, RTT);
}

/* Receiver (B) state */
static struct pkt recvbuf[SEQSPACE];
static bool recvd[SEQSPACE];
static int recv_base;

static bool in_recv_window(int x)
{
    int dist = (x - recv_base + SEQSPACE) % SEQSPACE;
    return (dist < WINDOWSIZE);
}

void B_init(void)
{
    int i;
    recv_base = 0;
    for (i = 0; i < SEQSPACE; i++)
    {
        recvd[i] = false;
    }
}

void B_input(struct pkt packet)
{
    int sn = packet.seqnum;
    struct pkt ackpkt;
    int i;

    /* sanity checks */
    assert(recv_base >= 0 && recv_base < SEQSPACE);
    printf("[DBG] B_input: recv seq=%d recv_base=%d\n", sn, recv_base);
    if (sn < 0 || sn >= SEQSPACE)
    {
        printf("[ERR] B_input: bogus seq %d\n", sn);
        return;
    }

    /* prepare ACK */
    ackpkt.seqnum = NOTINUSE;

    if (IsCorrupted(packet))
    {
        if (TRACE > 0)
            printf("----B: Corrupted packet, re-ACK %d\n", (recv_base + SEQSPACE - 1) % SEQSPACE);
        ackpkt.acknum = (recv_base + SEQSPACE - 1) % SEQSPACE;
    }
    else if (in_recv_window(sn) && !recvd[sn])
    {
        if (TRACE > 0)
            printf("----B: packet %d is correctly received, send ACK!\n", sn);
        recvbuf[sn] = packet;
        recvd[sn] = true;
        ackpkt.acknum = sn;
        /* deliver in-order */
        while (recvd[recv_base])
        {
            tolayer5(B, recvbuf[recv_base].payload);
            packets_received++;
            recvd[recv_base] = false;
            recv_base = (recv_base + 1) % SEQSPACE;
        }
    }
    else
    {
        if (TRACE > 0)
            printf("----B: Out-of-order packet %d, re-ACK %d\n",
                   sn, (recv_base + SEQSPACE - 1) % SEQSPACE);
        ackpkt.acknum = (recv_base + SEQSPACE - 1) % SEQSPACE;
    }

    /* build and send ACK */
    for (i = 0; i < 20; i++)
        ackpkt.payload[i] = '0';
    ackpkt.checksum = ComputeChecksum(ackpkt);
    tolayer3(B, ackpkt);
}

void B_output(struct msg message)
{
    /* unused for simplex */
}

void B_timerinterrupt(void)
{
    /* unused for simplex */
}
