#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "emulator.h"
#include "sr.h"

/* ******************************************************************
   Selective-Repeat Protocol
**********************************************************************/

#define RTT 16.0      /* round trip time.  MUST BE SET TO 16.0 when submitting assignment */
#define WINDOWSIZE 6  /* the maximum number of buffered unacked packet \
                        MUST BE SET TO 6 when submitting assignment */
#define SEQSPACE 7    /* the min sequence space for SR must be at least windowsize + 1 */
#define NOTINUSE (-1) /* used to fill header fields that are not being used */

/* Emulator counters (defined in emulator.c) */
extern int total_ACKs_received;
extern int new_ACKs;
extern int packets_resent;
extern int packets_received;
extern int window_full;

/* Compute checksum over header + payload */
int ComputeChecksum(struct pkt packet)
{
    int checksum;
    int i;

    checksum = packet.seqnum + packet.acknum;
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

/* Sender (A) */
static struct pkt buffer[SEQSPACE]; /* store packets by seq number */
static bool acked[SEQSPACE];
static int send_base;   /* oldest un-ACKed seq num */
static int next_seqnum; /* next new seq num */

/* is x in [send_base .. send_base+WINDOWSIZE-1] mod SEQSPACE? */
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

/* application layer calls A_output to send message */
void A_output(struct msg message)
{
    struct pkt p;
    int i;

    if (!in_send_window(next_seqnum))
    {
        /* window full: drop and count */
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

    /* trace & send */
    if (TRACE > 0)
        printf("----A: New message arrives, send window is not full, send new messge to layer3!\n");
    printf("Sending packet %d to layer 3\n", p.seqnum);
    tolayer3(A, p);

    /* start timer if this is base packet */
    if (send_base == next_seqnum)
    {
        starttimer(A, RTT);
    }

    next_seqnum = (next_seqnum + 1) % SEQSPACE;
}

/* network layer calls A_input when an ACK arrives */
void A_input(struct pkt packet)
{
    int ack;

    if (IsCorrupted(packet))
    {
        if (TRACE > 0)
            printf("----A: Corrupted ACK, ignoring\n");
        return;
    }

    ack = packet.acknum;
    if (in_send_window(ack) && !acked[ack])
    {
        /* valid new ACK */
        total_ACKs_received++;
        new_ACKs++;
        acked[ack] = true;
        if (TRACE > 0)
            printf("----A: uncorrupted ACK %d is received\n", ack);
        if (TRACE > 0)
            printf("----A: ACK %d is not a duplicate\n", ack);

        /* slide window over all acked packets */
        while (acked[send_base])
        {
            acked[send_base] = false;
            send_base = (send_base + 1) % SEQSPACE;
        }

        /* restart or stop timer */
        stoptimer(A);
        if (send_base != next_seqnum)
        {
            starttimer(A, RTT);
        }
    }
    else
    {
        if (TRACE > 0)
            printf("----A: ACK %d is a duplicate or out-of-window, ignoring\n", ack);
    }
}

/* timer interrupt for oldest un-ACKed packet */
void A_timerinterrupt(void)
{
    if (TRACE > 0)
        printf("----A: Timeout, resending packet %d\n", send_base);

    tolayer3(A, buffer[send_base]);
    packets_resent++;
    starttimer(A, RTT);
}

/* Receiver (B) */
static struct pkt recvbuf[SEQSPACE];
static bool recvd[SEQSPACE];
static int recv_base;

/* is x in [recv_base .. recv_base+WINDOWSIZE-1] mod SEQSPACE? */
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
    struct pkt ackpkt;
    int sn;
    int i;

    /* prepare ACK header */
    ackpkt.seqnum = NOTINUSE;

    if (IsCorrupted(packet))
    {
        if (TRACE > 0)
            printf("----B: Corrupted packet, re-ACK %d\n", (recv_base + SEQSPACE - 1) % SEQSPACE);
        ackpkt.acknum = (recv_base + SEQSPACE - 1) % SEQSPACE;
    }
    else
    {
        sn = packet.seqnum;
        if (in_recv_window(sn) && !recvd[sn])
        {
            /* correct packet */
            if (TRACE > 0)
                printf("----B: packet %d is correctly received, send ACK!\n", sn);

            recvbuf[sn] = packet;
            recvd[sn] = true;
            ackpkt.acknum = sn;

            /* deliver any in-order packets */
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
    }

    /* fill payload with zeros */
    for (i = 0; i < 20; i++)
    {
        ackpkt.payload[i] = '0';
    }
    ackpkt.checksum = ComputeChecksum(ackpkt);

    /* send ACK */
    tolayer3(B, ackpkt);
}

/* unused for simplex */
void B_output(struct msg message) {}
void B_timerinterrupt(void) {}
