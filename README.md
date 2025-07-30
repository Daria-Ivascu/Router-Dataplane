# Router Dataplane

In this project, I implemented the dataplane of a router, handling both the packet forwarding process and its control mechanisms.

## Completed requirements:

* Packet Forwarding – I implemented the transmission of IPv4 packets by following the steps in the assignment and referencing Lab 4, where this process was explained. I used a routing table to determine the best path for each packet, and once the best route was found, the packets were forwarded accordingly.

* Efficient Longest Prefix Match (LPM) – To improve the performance of route lookup in the routing table, I implemented a Trie structure to store IP addresses. To better understand the logic behind the Trie, I din some online research and found a helpful resource: https://vinesmsuic.github.io/notes-networkingIP-L3/. I added each prefix from the routing table into the Trie, checking at each step whether the current bit was 0 or 1 to decide whether to move left or right (left for 0, right for 1). Once I reached the end of the prefix, I stored the routing entry in that node. During the lookup phase, I traversed the Trie according to the destination IP address and found the best matching prefix.

* ARP Protocol – I implemented the ARP protocol by following the required steps so it could dynamically populate the ARP table. When an address doesn't have a valid ARP entry, an ARP request is sent out through the corresponding interface. Upon receiving an ARP reply, a new entry is created in the ARP table with the received information and the packet queue is checked for any packets that could now be forwarded using this entry (the rest of the packets were requeued to be processed later). When an ARP request is received, the router sends back an ARP reply if the target IP matched the IP address of the interface that received the request.

* ICMP Protocol – I implemented the ICMP protocol based on the assignment instructions. When the destination of a packet is the router itself, an "Echo reply" message is sent. If no route to the destination is found, the router sends a "Destination unreachable" message. Similarly, if a packet was dropped due to a TTL (Time To Live) expiration, a "Time exceeded" message is sent back.