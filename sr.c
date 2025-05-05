#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "emulator.h"
#include "sr.h"

/* ******************************************************************
   Selective-Repeat Protocol
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

/************************ Sender (A) ***************************/
static struct pkt buffer[SEQSPACE]; /* buffer packets by seqnum */
static bool acked[SEQSPACE];
static int send_base;
static int next_seqnum;

/* is x in [send_base .. send_base+WINDOWSIZE-1]? */
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
    struct pkt p;
    int i;

    if (in_send_window(next_seqnum))
    {
        if (TRACE > 1)
            printf("----A: New message arrives, send window is not full, send new messge to layer3!\n");
        p.seqnum = next_seqnum;
        p.acknum = NOTINUSE;
        for (i = 0; i < 20; i++)
            p.payload[i] = message.data[i];
        p.checksum = ComputeChecksum(p);

        /* buffer for potential retransmission */
        buffer[next_seqnum] = p;

        if (TRACE > 0)
            printf("Sending packet %d to layer 3\n", p.seqnum);
        tolayer3(A, p);

        if (send_base == next_seqnum)
            starttimer(A, RTT);

        next_seqnum = (next_seqnum + 1) % SEQSPACE;
    }
    else
    {
        if (TRACE > 0)
            printf("----A: New message arrives, send window is full\n");
        window_full++;
    }
}

void A_input(struct pkt packet)
{
    int acknum = packet.acknum;

    if (IsCorrupted(packet))
    {
        if (TRACE > 0)
            printf("----A: corrupted ACK is received, do nothing!\n");
        return;
    }

    if (in_send_window(acknum) && !acked[acknum])
    {
        if (TRACE > 0)
            printf("----A: uncorrupted ACK %d is received\n", acknum);
        total_ACKs_received++;
        if (TRACE > 0)
            printf("----A: ACK %d is not a duplicate\n", acknum);
        new_ACKs++;
        acked[acknum] = true;

        /* slide window */
        while (acked[send_base])
        {
            acked[send_base] = false;
            send_base = (send_base + 1) % SEQSPACE;
        }

        stoptimer(A);
        if (send_base != next_seqnum)
            starttimer(A, RTT);
    }
    else
    {
        if (TRACE > 0)
            printf("----A: duplicate ACK received, do nothing!\n");
    }
}

void A_timerinterrupt(void)
{
    if (TRACE > 0)
        printf("----A: time out,resend packets!\n");
    /* retransmit only the base packet */
    tolayer3(A, buffer[send_base]);
    packets_resent++;
    if (TRACE > 0)
        printf("---A: resending packet %d\n", buffer[send_base].seqnum);
    starttimer(A, RTT);
}

/*********************** Receiver (B) **************************/
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
        recvd[i] = false;
}

void B_input(struct pkt packet)
{
    int sn = packet.seqnum;
    struct pkt ackpkt;
    int i;

    if (!IsCorrupted(packet) && in_recv_window(sn) && !recvd[sn])
    {
        if (TRACE > 0)
            printf("----B: packet %d is correctly received, send ACK!\n", sn);
        recvbuf[sn] = packet;
        recvd[sn] = true;
        while (recvd[recv_base])
        {
            tolayer5(B, recvbuf[recv_base].payload);
            packets_received++;
            recvd[recv_base] = false;
            recv_base = (recv_base + 1) % SEQSPACE;
        }
        ackpkt.acknum = sn;
    }
    else
    {
        if (TRACE > 0)
            printf("----B: packet corrupted or not expected sequence number, resend ACK!\n");
        ackpkt.acknum = (recv_base + SEQSPACE - 1) % SEQSPACE;
    }

    ackpkt.seqnum = NOTINUSE;
    for (i = 0; i < 20; i++)
        ackpkt.payload[i] = '0';
    ackpkt.checksum = ComputeChecksum(ackpkt);
    tolayer3(B, ackpkt);
}

void B_output(struct msg message) {}

void B_timerinterrupt(void) {}
