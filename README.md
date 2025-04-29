# Project Mariana’s Qubit

![poster](poster.jpg)

Mariana’s Qubit is a next-generation, anonymous routing protocol, designed to build a fully functional and quantum-resilient network stack. While for a layman, it is similar to Tor, it is quite different at the fundamental and protocol level. Project Mariana’s Qubit builds an entire network stack, analogous to the OSI model to securely route traffic anonymously via relays and proxies. It is truly decentralized, unlike Tor which maintains a centralized relay list for bootstrapping. 

The system offers dynamic network topologies where nodes attempt to form a mesh network. For nodes on private subnets without internet connectivity, it attempts to perform local node discovery and forms a network with other nodes in the same subnet. If one of the machines in the private subnet is connected to the internet, probably via a second network interface, it automatically relays traffic from its subnet peers, making them reachable from anywhere on the Mariana Network without involving any manual setup.
For nodes that are in the routable internet, (not behind a NAT or private subnet), it automatically promotes itself to a ‘public node’ and adds itself to an open-source public relay list, maintained on Github. A node which is behind a NAT and does not have other nodes in the same private subnet may attempt to fetch the public relay list from Github and connect through that. It also maintains a persistent copy of the list on its disk so that it can access the same in case Github is not working. This copy of public relay list is often announced through the network so that other nodes can make a copy of it, thus making Github redundant when the network grows.

Each node on the network is identified by a randomized unique ID, also known as NAC (Network Address Code). Not by it’s IP or any other identifiable information. Nodes aiming for deeper anonymity may regularly rotate their NACs, while service hosting nodes can maintain persistent identities to remain reachable. The routing list of the network allows sending packets to the destination node by NAC. It uses a custom distance-vector routing protocol to work with NAC.

The system offers strong storm control mechanisms and self-healing. A node going down is automatically removed from the entire network within 60 seconds and a node coming online is automatically added to the routing tables almost instantaneously. 

The system performs optimized packet loss management. Unlike TCP, it does not send an ACK for every packet, which increases the overheads. Instead, the destination node makes a list of dropped packets by the sequence numbers of the same and requests retransmission from the source node. 

All packets transmitted over the network, containing payload, are encrypted by AES and Kyber 512 for post-quantum encryption ensuring it is resistant to attacks involving a large-scale quantum computer, thus providing a truly decentralized, anonymous network.

On the user end, it opens Chrome (or any browser) proxied through the Mariana Daemon. On the server side, or side of receiving node, it proxies the traffic to any service hosted with a web server like Apache2, Nginx or IIS. Hence, a developer may just develop a web application and let the Mariana Daemon route it over the Mariana’s Qubit network anonymously. In upcoming versions of Mariana’s Qubit, it is aimed to be able to proxy traffic to any socket, making it a truly protocol-agnostic anonymity network.

## Dependencies
* Python 3.12 or above
* Cryptography
* psutil
* requests
* flask
* Chrome or any other browser that supports using proxy server

## Installation and set-up
* Clone this repository
* Install dependencies
* Start `proxyserver.py`
* Start web browser with proxy to `http://localhost:8000`
* Add a service to start `proxyserver.py` every time the computer boots up.

## Special notes for public nodes
* Public nodes are defined as nodes that are not behind a NAT and are driectly accessible over the internet
* Public nodes are requested to volunteer to be a public relay
* To be a public relay, after first start of the program, a config.json file is generated. Check the port number in that file. Allow that port on your firewall for any inbound and outbound UDP traffic.

## Special notes for people who want to maintain anonymity
* Add a service to frequently delete `config.json` and `privatekey.pem`

# Special note for public nodes who want anonymity
* Add a service to frequently modify the `config.json` to set NAC to a random UUID v4 string. Do not delete the config file as that will reset the port number and you might have to re-configure that from firewall.
* The service may delete the `privatekey.pem` file to rotate keypair.
