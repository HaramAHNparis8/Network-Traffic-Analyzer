#ifndef PACKET_H
#define PACKET_H

typedef struct Packet{
	double timestamp;
	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
	unsigned char protocol;
	unsigned int length;

}Packet;


#endif
