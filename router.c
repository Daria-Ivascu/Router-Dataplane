#include <arpa/inet.h> 
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "protocols.h"
#include "queue.h"
#include "lib.h"

#define ETHR_TYPE_IP 0x0800
#define ETHR_TYPE_ARP 0x0806

// routing table
struct route_table_entry *routing_table;
int routing_table_len;

// ARP table
struct arp_table_entry *arp_table;
int arp_table_len;

// struct that defines a node in the trie
typedef struct trie_node {
	// at the end of the route, we store the entry
	struct route_table_entry *routing_entry;

	// the child nodes (for bit 0 and bit 1)
	struct trie_node *left_0, *right_1;
} trie_node, *Trie;

// creates a node for the trie
Trie create_node() {
	// allocates memory for the node
	Trie node = malloc(sizeof(trie_node));
	DIE(node == NULL, "memory");

	// initialize the children and the routing entry
	node->left_0 = NULL;
	node->right_1 = NULL;
	node->routing_entry = NULL;

	return node;
}

// inserts a node in the trie
void insert_node(Trie root, struct route_table_entry *routing_entry) {
	// if the mask is 0, we insert the entry directly in the root
	if (routing_entry->mask == 0) {
		if (root == NULL)
            root = create_node();

		root->routing_entry = routing_entry;
		return;
	}

	// starts from the most significant bit
	int bit_pos = 31;
	
	// converts the prefix and the mask to host byte order
	uint32_t current_prefix = ntohl(routing_entry->prefix);
	uint32_t current_mask = ntohl(routing_entry->mask);

	Trie current_node = root;

	// marks only the valid bits (the ones where the mask has 1s)
	while (bit_pos >= 0 && (current_mask & (1 << bit_pos))) {
		// gets the current bit from the prefix by shifting it with 
		// bit_pos bits and extracts the first one
		int current_bit = (current_prefix >> bit_pos) & 1;

		// if the bit is 0, we go left, otherwise, we go right
		// if the child nodes don't exist, we create them
		if (current_bit == 0) {
			if (current_node->left_0 == NULL) 
				current_node->left_0 = create_node();
			
			current_node = current_node->left_0;
		} else {
			if (current_node->right_1 == NULL) 
				current_node->right_1 = create_node();
			
			current_node = current_node->right_1;
		}

		bit_pos--;
	}

	// ends traversing the significant bits, so we store the routing entry
	current_node->routing_entry = routing_entry;
}

// searches the LPM in the trie for the destination IP
struct route_table_entry *get_best_route_match(Trie root, uint32_t ip_dest) {
	struct route_table_entry *best = NULL;
	int bit_pos = 31;
	Trie current_node = root;

	// searches the destination IP bits in the trie
	while (bit_pos >= 0 && current_node != NULL) {
		// if we ended the current prefix, we got its routing entry and we check
		// if it matched the routing entry of the destination IP 
		if (current_node->routing_entry != NULL) {
			uint32_t current_prefix = current_node->routing_entry->prefix;
			uint32_t current_mask = current_node->routing_entry->mask;
		
			if ((ntohl(current_prefix) & ntohl(current_mask)) == (ntohl(ip_dest) & ntohl(current_mask))) {
				if (best == NULL || (ntohl(best->mask) < ntohl(current_mask)))
					best = current_node->routing_entry;
			}
		}

		// extracts the current bit of the destion IP (to see in which node to go next)
		int current_bit = (ntohl(ip_dest) >> bit_pos) & 1;

		if (current_bit == 0)
			current_node = current_node->left_0;
		else
			current_node = current_node->right_1;
		
		bit_pos--;
	}

	return best;
}

// creates the ICMP reply for the router (Echo reply)
void icmp_router(char *buf, struct ether_hdr *eth_hdr, struct ip_hdr *ip_hddr, int interface) {
	// extracts the ICMP header
	struct icmp_hdr *icmp_hddr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

	// in the Ethernet header, the destination MAC address will be updated to the MAC addres from the received packet
	memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);

	// the source MAC address will be updated to the one from the interface
	get_interface_mac(interface, eth_hdr->ethr_shost);

	// also in the IP header, the source and destination addresses are swapped
	uint32_t aux;
	aux = ip_hddr->source_addr;
	ip_hddr->source_addr = ip_hddr->dest_addr;
	ip_hddr->dest_addr = aux;

	// recalculates the checksum for the IP header
	ip_hddr->checksum = 0;
	ip_hddr->checksum = htons(checksum((uint16_t *)ip_hddr, sizeof(struct ip_hdr)));

	// updates the ICMP header
	icmp_hddr->mtype = 0;
	icmp_hddr->mcode = 0;
	icmp_hddr->check = 0;
	icmp_hddr->check = htons(checksum((uint16_t *)icmp_hddr, sizeof(struct icmp_hdr)));
}

// creates the ICMP packet more generally
void icmp_packet(uint8_t type, char *buf, int interface, struct ether_hdr *eth_hdr_recv, struct ip_hdr *ip_hddr_recv) {
	// the size of the original data datagram
	int data_datagram_len = 8;
 
	// allocates memory for a new ICMP packet
	void *icmp_packet = malloc(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + data_datagram_len);
	
	// extracts the headers from the packet
	struct ether_hdr *eth_hdr = (struct ether_hdr *)icmp_packet;
	struct ip_hdr *ip_hddr = (struct ip_hdr *)(icmp_packet + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp_hddr = (struct icmp_hdr *)(icmp_packet + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

	// updates the Ethernet header in the ICMP packet
	memcpy(eth_hdr->ethr_dhost, eth_hdr_recv->ethr_dhost, 6);
	memcpy(eth_hdr->ethr_shost, eth_hdr_recv->ethr_shost, 6);
	eth_hdr->ethr_type = htons(ETHR_TYPE_IP);

	// updates the IP header of the ICMP packet
	ip_hddr->ver = 4;
	ip_hddr->ihl = 5;
	ip_hddr->tos = 0;
	ip_hddr->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + data_datagram_len);
	ip_hddr->id = 0;
	ip_hddr->frag = 0;
	ip_hddr->ttl = 64;
	ip_hddr->proto = 1;

	// transforms the IP address in binary
	uint32_t binary_ip;
	inet_pton(AF_INET, get_interface_ip(interface), &binary_ip);

	ip_hddr->source_addr = binary_ip;
	ip_hddr->dest_addr = ip_hddr_recv->source_addr;

	// recalculates the checksum of the IP header
	ip_hddr->checksum = 0;
	ip_hddr->checksum = htons(checksum((uint16_t *)ip_hddr, sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + data_datagram_len));

	// updates the ICMP header
	icmp_hddr->mtype = type;
	icmp_hddr->mcode = 0;

	// copies the received IP header and the first 8 bytes
	memcpy((void *)icmp_hddr + sizeof(struct icmp_hdr), ip_hddr_recv, sizeof(struct ip_hdr) + data_datagram_len);

	// recalculates the checksum of the ICMP header
	icmp_hddr->check = 0;
	icmp_hddr->check = htons(checksum((uint16_t *)icmp_hddr, sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + data_datagram_len));

	// sends the ICMP packet
	send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + data_datagram_len, (char *)icmp_packet, interface);
}

// iterates through the ARP table and searches for an entry that matches the given_ip
struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
	for (int i = 0; i < arp_table_len; i++)
		if (arp_table[i].ip == given_ip)
			return &arp_table[i];
	return NULL;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	// alocates space for the routing table
	routing_table = malloc (sizeof(struct route_table_entry) * 100000);
	DIE(routing_table == NULL, "memory");

	// reads the routing table 
	routing_table_len = read_rtable(argv[1], routing_table);

	// allocates space for the ARP table
	arp_table = malloc (sizeof(struct arp_table_entry) * 100000);
	DIE(arp_table == NULL, "memory");

	// reads the static ARP table
	//arp_table_len = parse_arp_table("not_arp_table.txt", arp_table);

	// number of elements of the ARP table
	arp_table_len = 0;

	// initializes a queue for the packets
	struct queue *p_queue = create_queue();

	// creates the trie for the prefiexes in the routing table
	Trie trie = create_node();
	for (int i = 0; i < routing_table_len; i++)
		insert_node(trie, routing_table + i);

	while (1) {

		size_t interface;
		size_t len;
		
		// used to store the IP address in binary form
		uint32_t dest_ip;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

    	// TODO: Implement the router forwarding logic

		// extracts the Ethernet header of the packet 
		struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;

		// extracts the IP header of the packet
		struct ip_hdr *ip_hddr = (struct ip_hdr *) (buf + sizeof(struct ether_hdr));

		// checks if we got an IPV4 packet
		if (ntohs(eth_hdr->ethr_type) == ETHR_TYPE_IP) {
			
			// checks if we have the final destination by transforming the IP of the interface in binary form
			inet_pton(AF_INET, get_interface_ip(interface), &dest_ip);
			if (ip_hddr->dest_addr == dest_ip) {

				// if we have the final destination (router case), we generate the ICMP packet
				icmp_router(buf, eth_hdr, ip_hddr, interface);

				// sends "Echo reply" ICMP packet
				send_to_link(len, (char *)buf, interface);

				continue;
			} else {
				// checks the ip_hddr integrity using checksum
				if (checksum((uint16_t *) ip_hddr, sizeof(struct ip_hdr)) != 0)
					continue;

				// checks the TTL of the packet and updates it accordingly
				if (ip_hddr->ttl <= 1) {
					// sends "Time exceeded" ICMP packet if there is no TTL left
					icmp_packet(11, buf, interface, eth_hdr, ip_hddr);
					continue;
				}
				
				ip_hddr->ttl--;
				ip_hddr->checksum = 0;

				// searches the IP address in the routing_table
				struct route_table_entry *best_match = get_best_route_match(trie, ip_hddr->dest_addr);
				if (best_match == NULL) {
					// sends "Destination Unreachable" ICMP packet if there is no match
					icmp_packet(3, buf, interface, eth_hdr, ip_hddr);
					continue;
				}

				// updates the checksum of the packet
				ip_hddr->checksum = htons(checksum((uint16_t *) ip_hddr, sizeof(struct ip_hdr)));

				// updates the L2 addresses
				get_interface_mac(best_match->interface, eth_hdr->ethr_shost);
				struct arp_table_entry *mac_address = get_arp_entry(best_match->next_hop);

				if (mac_address == NULL) {
					// stores the processed packet in queue
					// in the queue we will put a copy of the packet so that we don't use buf (a reutilized buffer)
					void *current_packet = malloc(len);
					DIE(current_packet == NULL, "memory");
					memcpy(current_packet, buf, len);
					queue_enq(p_queue, current_packet);

					// generates an ARP packet
					void *arp_packet = malloc(sizeof(struct ether_hdr) + sizeof(struct arp_hdr));
					DIE(arp_packet == NULL, "memory");

					// extracts the Ethernet header of the packet
					struct ether_hdr *eth_hdr_arp_packet = (struct ether_hdr *)arp_packet;
					
					// initializes the packet
					get_interface_mac(best_match->interface, eth_hdr_arp_packet->ethr_shost);

					// the request will be sent through broadcast
					memset(eth_hdr_arp_packet->ethr_dhost, 0xff, 6);

					eth_hdr_arp_packet->ethr_type = htons(ETHR_TYPE_ARP);

					// extracts the ARP header
					struct arp_hdr *arp_hdr_arp_packet = (struct arp_hdr *)(arp_packet + sizeof(struct ether_hdr));

					// initializes the ARP header
					arp_hdr_arp_packet->hw_type = htons(1);
					arp_hdr_arp_packet->hw_len = 6;
					arp_hdr_arp_packet->proto_type = htons(ETHR_TYPE_IP);
					arp_hdr_arp_packet->proto_len = 4;
					arp_hdr_arp_packet->opcode = htons(1);

					// sender and target hardware addresses
					get_interface_mac(best_match->interface, arp_hdr_arp_packet->shwa);
					memset(arp_hdr_arp_packet->thwa, 0, 6);

					// sender and target IP addresses
					uint32_t binary_ip;
					inet_pton(AF_INET, get_interface_ip(best_match->interface), &binary_ip);

					arp_hdr_arp_packet->sprotoa = binary_ip;
					arp_hdr_arp_packet->tprotoa = best_match->next_hop;

					//send the ARP request
					send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), (char *)arp_packet, best_match->interface);

					continue;
				}

				memcpy(eth_hdr->ethr_dhost, mac_address->mac, 6);

				// send the packet forward
				send_to_link(len, buf, best_match->interface);		
			}
	} else if (ntohs(eth_hdr->ethr_type) == ETHR_TYPE_ARP) {
		// extracts the ARP header from the packet
		struct arp_hdr *arp_hdr_recv = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

		// checks if we have an ARP request or an ARP reply
		if (ntohs(arp_hdr_recv->opcode) == 1) {
			uint32_t check;
			inet_pton(AF_INET, get_interface_ip(interface), &check);

			// checks if the MAC address matches the one of the interface that received the request
			if  (arp_hdr_recv->tprotoa == check) {
				// updates the ARP header
				// updates the IPs, the source and destination addresses are swapped
				uint32_t aux;
				aux = arp_hdr_recv->tprotoa;
				arp_hdr_recv->tprotoa = arp_hdr_recv->sprotoa;
				arp_hdr_recv->sprotoa = aux;

				// the target address is now the source address
				memcpy(arp_hdr_recv->thwa, arp_hdr_recv->shwa, 6);

				// the source address will be the MAC address of the interface that received the request
				uint8_t *mac = malloc(6);
				get_interface_mac(interface, mac);
				memcpy(arp_hdr_recv->shwa, mac, 6);

				arp_hdr_recv->opcode = htons(2);
				
				// updated the Ethernet header
				// we send the reply back to the sender, so the destination will be the same as the sender's
				// and the sender MAC will be the MAC of the interface that received the request
				memcpy(eth_hdr->ethr_dhost, arp_hdr_recv->thwa, 6);
				memcpy(eth_hdr->ethr_shost, arp_hdr_recv->shwa, 6);

				send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), buf, interface);
			}
		} else if (ntohs(arp_hdr_recv->opcode) == 2) {
			// we have to deal with an ARP reply
			// creates a new entry and adds it in the ARP table
			arp_table[arp_table_len].ip = arp_hdr_recv->sprotoa;
			memcpy(arp_table[arp_table_len].mac, arp_hdr_recv->shwa, 6);
			arp_table_len++;

			// creates a new queue where the unused packets will be stored
			struct queue *left_packets = create_queue();

			// starts to iterate through the queue
			while (!queue_empty(p_queue)) {
				// extracts the current packet from the queue
				void *packet = queue_deq(p_queue);

				// extracts the Ethernet header and the IP header from the packet
				struct ether_hdr *packet_ethr_hdr = (struct ether_hdr *)packet;
				struct ip_hdr *packet_ip_hdr = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));
				
				// recalculates the best match in the trie and the match in the ARP table
				struct route_table_entry *current_best_match = get_best_route_match(trie, packet_ip_hdr->dest_addr);

				// checks if the MAC address of the packet exists
				// if it doesn't, we put the packet in the new queue
				if (arp_table[arp_table_len - 1].ip == current_best_match->next_hop) {
					// updates the source address to the MAC address of the next hop
					get_interface_mac(current_best_match->interface, packet_ethr_hdr->ethr_shost);
					
					// updates the destination address to the found MAC address
					memcpy(packet_ethr_hdr->ethr_dhost, arp_table[arp_table_len - 1].mac, 6);

					packet_ethr_hdr->ethr_type = htons(ETHR_TYPE_IP);

					// sends the packet forward
					send_to_link(len, packet, current_best_match->interface);
				} else
					queue_enq(left_packets, (char *)packet);
			}

			// updates the packets queue
			p_queue = left_packets;
		}
	}


    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */


	}
}

