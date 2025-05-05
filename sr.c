#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "emulator.h"
#include "sr.h"

/* ******************************************************************
   Selective-Repeat Protocol (C89-compliant)
**********************************************************************/

#define RTT 16.0     /* MUST be set to 16.0 for submission */
#define WINDOWSIZE 6 /* MUST be set to 6 for submission */
#define SEQSPACE (WINDOWSIZE + 1)
#define NOTINUSE (-1)

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

/*––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––*/
/*                        SENDER (A) state                        */
/*––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––*/

static struct pkt buffer[SEQSPACE]; /* store packets by seq number */
static bool acked[SEQSPACE];
static int send_base;   /* oldest un-ACKed seq num */
static int next_seqnum; /* next new seq num */

/* is x in [send_base .. send_base+WINDOWSIZE-1] mod SEQSPACE? */
static bool in_send_window(int x)
{
    int dist;
    dist = (x - send_base + SEQSPACE) % SEQSPACE;
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
            printf("----A_output: window full, dropping message\n");
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

    /* buffer & send */
    buffer[next_seqnum] = p;
    if (TRACE > 0)
        printf("----A_output: sending packet %d\n", p.seqnum);
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
            printf("----A_input: corrupted ACK, ignoring\n");
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
            printf("----A_input: received ACK %d\n", ack);

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
            printf("----A_input: duplicate/out-of-window ACK %d, ignoring\n", ack);
    }
}

/* timer interrupt for oldest un-ACKed packet */
void A_timerinterrupt(void)
{
    if (TRACE > 0)
        printf("----A_timerinterrupt: timeout, resending packet %d\n", send_base);

    tolayer3(A, buffer[send_base]);
    packets_resent++;
    if (TRACE > 0)
        printf("----A_timerinterrupt: restarted timer for %d\n", send_base);
    starttimer(A, RTT);
}

/*––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––*/
/*                       RECEIVER (B) state                       */
/*––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––*/

static struct pkt recvbuf[SEQSPACE];
static bool recvd[SEQSPACE];
static int recv_base;
static int B_nextseqnum;

/* is x in [recv_base .. recv_base+WINDOWSIZE-1] mod SEQSPACE? */
static bool in_recv_window(int x)
{
    int dist;
    dist = (x - recv_base + SEQSPACE) % SEQSPACE;
    return (dist < WINDOWSIZE);
}

void B_init(void)
{
    int i;

    recv_base = 0;
    B_nextseqnum = 1;
    for (i = 0; i < SEQSPACE; i++)
    {
        recvd[i] = false;
    }
}

void B_input(struct pkt packet)
{
    struct pkt ackpkt;
    int i;
    int sn;

    /* prepare ACK pkt fields */
    ackpkt.seqnum = B_nextseqnum;
    B_nextseqnum = (B_nextseqnum + 1) % 2;

    if (IsCorrupted(packet))
    {
        /* corrupted: re-ACK last in-order */
        if (TRACE > 0)
            printf("----B_input: corrupted packet, re-ACK %d\n", (recv_base + SEQSPACE - 1) % SEQSPACE);
        ackpkt.acknum = (recv_base + SEQSPACE - 1) % SEQSPACE;
    }
    else
    {
        sn = packet.seqnum;
        if (in_recv_window(sn) && !recvd[sn])
        {
            /* buffer and ACK */
            recvbuf[sn] = packet;
            recvd[sn] = true;
            ackpkt.acknum = sn;
            if (TRACE > 0)
                printf("----B_input: buffering packet %d, sending ACK\n", sn);

            /* deliver any in-order packets */
            while (recvd[recv_base])
            {
                if (TRACE > 0)
                    printf("----B_input: delivering packet %d to layer5\n", recv_base);
                tolayer5(B, recvbuf[recv_base].payload);
                recvd[recv_base] = false;
                recv_base = (recv_base + 1) % SEQSPACE;
            }
        }
        else
        {
            /* duplicate/out-of-window: re-ACK last in-order */
            if (TRACE > 0)
                printf("----B_input: out-of-order packet %d, re-ACK %d\n", sn, (recv_base + SEQSPACE - 1) % SEQSPACE);
            ackpkt.acknum = (recv_base + SEQSPACE - 1) % SEQSPACE;
        }
    }

    /* fill payload with zeros */
    for (i = 0; i < 20; i++)
    {
        ackpkt.payload[i] = '0';
    }
    ackpkt.checksum = ComputeChecksum(ackpkt);

    if (TRACE > 0)
        printf("----B_input: sending ACK %d\n", ackpkt.acknum);
    tolayer3(B, ackpkt);
}

/* unused for simplex */
void B_output(struct msg message) {}
void B_timerinterrupt(void) {}
