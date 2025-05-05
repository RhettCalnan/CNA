#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "emulator.h"
#include "sr.h"

/* ******************************************************************
   Selective-Repeat Protocol
**********************************************************************/

#define RTT 16.0     /* MUST be 16.0 when submitting */
#define WINDOWSIZE 6 /* MUST be 6 when submitting */
#define SEQSPACE (WINDOWSIZE + 1)
#define NOTINUSE (-1)

/* Compute checksum over header + payload */
int ComputeChecksum(struct pkt packet)
{
    int checksum = packet.seqnum + packet.acknum;
    for (int i = 0; i < 20; i++)
        checksum += (int)packet.payload[i];
    return checksum;
}

bool IsCorrupted(struct pkt packet)
{
    return (packet.checksum != ComputeChecksum(packet));
}

/*––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––*/
/*                        SENDER (A) state                        */
/*––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––*/

/* buffer a copy of every packet by its sequence number */
static struct pkt buffer[SEQSPACE];
/* have we received an ACK for sequence i? */
static bool acked[SEQSPACE];
static int send_base;   /* oldest un-ACKed seq num */
static int next_seqnum; /* next new seq num to use */

/* is sequence x in the current send window? */
static bool in_send_window(int x)
{
    int dist = (x - send_base + SEQSPACE) % SEQSPACE;
    return (dist < WINDOWSIZE);
}

/* initialize sender state */
void A_init(void)
{
    send_base = 0;
    next_seqnum = 0;
    for (int i = 0; i < SEQSPACE; i++)
        acked[i] = false;
}

/* from application layer: try to send a new message */
void A_output(struct msg message)
{
    if (!in_send_window(next_seqnum))
    {
        /* window is full—drop or buffer at higher layer */
        if (TRACE > 0)
            printf("----A_output: window full, dropping message\n");
        return;
    }

    /* build packet */
    struct pkt p;
    p.seqnum = next_seqnum;
    p.acknum = NOTINUSE;
    for (int i = 0; i < 20; i++)
        p.payload[i] = message.data[i];
    p.checksum = ComputeChecksum(p);

    /* buffer and send */
    buffer[next_seqnum] = p;
    if (TRACE > 0)
        printf("----A_output: sending packet %d\n", p.seqnum);
    tolayer3(A, p);

    /* start timer if this is the base packet */
    if (send_base == next_seqnum)
        starttimer(A, RTT);

    next_seqnum = (next_seqnum + 1) % SEQSPACE;
}

/* from network layer: an ACK has arrived */
void A_input(struct pkt packet)
{
    if (IsCorrupted(packet))
    {
        if (TRACE > 0)
            printf("----A_input: received corrupted ACK, ignoring\n");
        return;
    }

    int ack = packet.acknum;
    if (in_send_window(ack) && !acked[ack])
    {
        if (TRACE > 0)
            printf("----A_input: received ACK %d\n", ack);
        acked[ack] = true;

        /* slide send_base forward over any newly ACKed packets */
        while (acked[send_base])
        {
            acked[send_base] = false; /* clear for next wrap */
            send_base = (send_base + 1) % SEQSPACE;
        }

        /* restart or stop timer */
        stoptimer(A);
        if (send_base != next_seqnum)
        {
            /* still outstanding packets—timer for new oldest */
            starttimer(A, RTT);
        }
    }
    else
    {
        if (TRACE > 0)
            printf("----A_input: duplicate or out-of-window ACK %d, ignoring\n", ack);
    }
}

/* timer expired for the oldest un-ACKed packet */
void A_timerinterrupt(void)
{
    if (TRACE > 0)
        printf("----A_timerinterrupt: timeout, resending packet %d\n", send_base);

    /* retransmit only the oldest outstanding packet */
    tolayer3(A, buffer[send_base]);
    if (TRACE > 0)
        printf("----A_timerinterrupt: restarted timer for %d\n", send_base);
    starttimer(A, RTT);
}

/*––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––*/
/*                       RECEIVER (B) state                       */
/*––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––*/

/* buffer for out-of-order packets */
static struct pkt recvbuf[SEQSPACE];
static bool recvd[SEQSPACE];
static int recv_base;    /* next expected in-order seq num */
static int B_nextseqnum; /* seqnum field for ACK packets */

/* is sequence x in the current receive window? */
static bool in_recv_window(int x)
{
    int dist = (x - recv_base + SEQSPACE) % SEQSPACE;
    return (dist < WINDOWSIZE);
}

/* initialize receiver state */
void B_init(void)
{
    recv_base = 0;
    B_nextseqnum = 1;
    for (int i = 0; i < SEQSPACE; i++)
        recvd[i] = false;
}

/* from network layer: data packet has arrived */
void B_input(struct pkt packet)
{
    struct pkt ackpkt;
    int i;

    /* prepare ACK packet header */
    ackpkt.seqnum = B_nextseqnum;
    B_nextseqnum = (B_nextseqnum + 1) % 2; /* just toggle for trace */

    /* if corrupted, send ACK for last in-order */
    if (IsCorrupted(packet))
    {
        if (TRACE > 0)
            printf("----B_input: corrupted packet, re-ACK %d\n", (recv_base + SEQSPACE - 1) % SEQSPACE);
        ackpkt.acknum = (recv_base + SEQSPACE - 1) % SEQSPACE;
    }
    else
    {
        int sn = packet.seqnum;
        if (in_recv_window(sn) && !recvd[sn])
        {
            /* buffer it */
            if (TRACE > 0)
                printf("----B_input: buffering packet %d, sending ACK\n", sn);
            recvbuf[sn] = packet;
            recvd[sn] = true;
            ackpkt.acknum = sn;

            /* deliver any in-order sequence at front of buffer */
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
            /* duplicate or out-of-window—re-ACK last in-order */
            if (TRACE > 0)
                printf("----B_input: out-of-order packet %d, re-ACK %d\n",
                       sn, (recv_base + SEQSPACE - 1) % SEQSPACE);
            ackpkt.acknum = (recv_base + SEQSPACE - 1) % SEQSPACE;
        }
    }

    /* fill unused payload with zeros */
    for (i = 0; i < 20; i++)
        ackpkt.payload[i] = '0';
    ackpkt.checksum = ComputeChecksum(ackpkt);

    /* send the ACK */
    if (TRACE > 0)
        printf("----B_input: sending ACK %d\n", ackpkt.acknum);
    tolayer3(B, ackpkt);
}

/* unused for simplex */
void B_output(struct msg message) {}

void B_timerinterrupt(void) {}
