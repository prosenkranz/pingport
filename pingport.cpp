// PingPort
// Copyright (c) 2016, prosenkranz
//
// Tries to connect to a tcp port on a remote host and waits for any response
// This tool uses raw sockets, so it has to be run with root privileges.
//
// TODO:
// 	- Add UDP support
//	- Add IPv6 support

#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <chrono>
#include <thread>
#include <numeric>
#include <errno.h>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <net/if.h>
#include <arpa/inet.h>

using namespace std;

#define TEST_PACKET_SIZE sizeof(struct tcphdr)
#define DEFAULT_TIMEOUT 2
#define DEFAULT_REPEAT false

#define REQUIRE(cond, errmsg) if (!(cond)) { cerr << "Error: " << errmsg << endl; exit(1); }

// Returns the given integer ip-address as a string
string ip_to_str(uint32_t ip)
{
	struct in_addr addr;
	addr.s_addr = ip;
	return inet_ntoa(addr);
}

void print_help()
{
	cout << "Usage: pingport [OPTIONS] <HOST> <PORT>" << endl << endl;
	cout << "HOST: Can be either an ip address or a resolvable DNS address" << endl;
	cout << "PORT: The port to check on HOST" << endl;
	cout << "OPTIONS:" << endl <<
			"	-t n, --timeout n: Max. time to wait for a response in sec (default: " << DEFAULT_TIMEOUT << ")" << endl <<
			"	-r, --repeat: Repeat test until stopped via CTRL+C (default: " << (DEFAULT_REPEAT ? "on" : "off") << endl;
}

// Returns the IPv4 address of the host or 0 if host is invalid
uint32_t parse_host(const char* host)
{
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; // TODO: Use AF_UNSPEC to also allow IPv6

	struct addrinfo* addrinfo = 0;
	int res = getaddrinfo(host, 0, &hints, &addrinfo);
	if (res != 0) {
		cout << "Error: ";
		if (res == EAI_ADDRFAMILY) cout << "EAI_ADDRFAMILY";
		if (res == EAI_AGAIN) cout << "EAI_AGAIN";
		if (res == EAI_BADFLAGS) cout << "EAI_BADFLAGS";
		if (res == EAI_FAIL) cout << "EAI_FAIL";
		if (res == EAI_FAMILY) cout << "EAI_FAMILY";
		if (res == EAI_MEMORY) cout << "EAI_MEMORY";
		if (res == EAI_NODATA) cout << "EAI_NODATA";
		if (res == EAI_NONAME) cout << "EAI_NONAME";
		if (res == EAI_SERVICE) cout << "EAI_SERVICE";
		if (res == EAI_SOCKTYPE) cout << "EAI_SOCKTYPE";
		if (res == EAI_SYSTEM) cout << "EAI_SYSTEM";
		cout << endl;
		return 0;
	}

	struct sockaddr_in* addr = (struct sockaddr_in*)addrinfo->ai_addr;
	uint32_t hostip = addr->sin_addr.s_addr;
	freeaddrinfo(addrinfo);

	return hostip;
}


/*
	96 bit (12 bytes) pseudo header needed for tcp header checksum calculation
*/
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

/*
	Generic checksum calculation function
	http://www.binarytides.com/raw-udp-sockets-c-linux/
*/
unsigned short csum(unsigned short *ptr,int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;

	return(answer);
}

/*
	Fills the checksum field of the TCP header using the existing data in tcp
	and the given source and destination IP addresses.
	This method assumes that the TCP packet does not contain any data.
*/
void tcp_checksum(in_addr_t saddr, in_addr_t daddr, struct tcphdr* tcp)
{
	/* see RFC793 */
	struct pseudo_header psh;
	psh.source_address = saddr;
	psh.dest_address = daddr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));

	int pshsz = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
	char* pseudogram = (char*)malloc(pshsz);
	memcpy(pseudogram, (void*)&psh, sizeof(psh));
	memcpy(pseudogram + sizeof(psh), (void*)tcp, sizeof(struct tcphdr));

	tcp->check = csum((unsigned short*)pseudogram, pshsz);
	free(pseudogram);
}

// Binds given socket to a random port and given ip address
// Returns the port that the socket was bound to
unsigned short bind_to_random_port(int sock, uint32_t ip)
{
	unsigned short port;
	struct sockaddr_in addr;
	srand(time(0));
	while (true) {
		unsigned short port = (unsigned short)(49152 + (rand() % (65534 - 49152 + 1)));

		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = (in_addr_t)ip;

		if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
			if (errno == EADDRINUSE)
				continue;
			else
				port = 0;
		}

		return port;
	}
}

string get_default_route_iface()
{
	string defrouteiface = "eth0";

	ifstream routefile("/proc/net/route");
	if (!routefile.good()) {
		cout << "Failed open /proc/net/route" << endl;
		return defrouteiface;
	}

	string line;
	while (getline(routefile, line)) {
		istringstream iss(line);
		string iface;
		string destination;
		if (!(iss >> iface >> destination))
			continue;
		if (destination == "00000000") {
			defrouteiface = iface;
			break;
		}
	}

	routefile.close();
	return defrouteiface;
}

// Prints detailed information about the given tcp header
void parse_tcp_header(const struct tcphdr* tcp)
{
	/*cout << "\tRaw data: "; {
		for (int i = 0; i < sizeof(struct tcphdr); ++i) {
			printf("%02x ", ((unsigned char*)tcp)[i]);
		}
		printf("\n");
	}*/
	cout << ntohs(tcp->source) << " -> " << ntohs(tcp->dest) <<
			"; Seq: " << ntohl(tcp->seq) << "; Ack: " << ntohl(tcp->ack_seq) <<
			"; Win: " << tcp->window <<
			"; ";
	{
		if (tcp->syn) cout << "SYN ";
		if (tcp->ack) cout << "ACK ";
		if (tcp->rst) cout << "RST ";
		if (tcp->fin) cout << "FIN ";
		if (tcp->psh) cout << "PSH ";
		if (tcp->urg) cout << "URG ";
		if (tcp->ece) cout << "ECE ";
		if (tcp->cwr) cout << "CWR ";
	}
	cout << endl;
}

enum ETestPacketType
{
	eTESTPACKET_SYN,
	eTESTPACKET_RST
};

// syn and rst should not both be true!
bool send_tcp_packet(int sock,
					 uint32_t srcip, int srcport,
					 uint32_t destip, int destport,
					 ETestPacketType type)
{
	char packet[TEST_PACKET_SIZE];
	memset(packet, 0, TEST_PACKET_SIZE);
	struct tcphdr* tcp = (struct tcphdr*)packet;
	tcp->source = htons(srcport);
	tcp->dest = htons(destport);
	tcp->window = htons(1024);
	tcp->doff = 5; // data offset: 5x32bit words
	tcp->syn = (type == eTESTPACKET_SYN ? 1 : 0);
	tcp->rst = (type == eTESTPACKET_RST ? 1 : 0);

	tcp_checksum(srcip, destip, tcp);

	struct sockaddr_in daddr;
	daddr.sin_family = AF_INET;
	daddr.sin_port = IPPROTO_TCP;
	daddr.sin_addr.s_addr = destip;
	if (sendto(sock, (void*)packet, TEST_PACKET_SIZE, 0, (struct sockaddr*)&daddr, sizeof(daddr)) == -1) {
		cout << "Failed sendto()" << endl;
		return false;
	}

	return true;
}

// Summary:
//		Sends a TCP SYN packet to the given IP on the given Port and waits for a
//		response which can either be a RST or ACK packet.
// Returns:
//		False if an error occured, True otherwise
// Parameters:
//   	sock - a socket that can be reused for multiple tests, that should be
//   		   created with AF_INET, SOCK_RAW and IPPROTO_TCP and parameters.
//		ip - the ip of the host to ping
// 		port - the port to try to access
// 		timeout - maximum time to wait for a response in seconds
bool do_test(int sock, uint32_t ip, unsigned short port, uint32_t srcip,
			 unsigned short srcport, unsigned short timeout)
{
	cout << "Attempting " << ip_to_str(srcip) << ":" << srcport
		 << " -> " << ip_to_str(ip) << ":" << port << " ..." << endl;

	cout << "  ";

	// Set timeout
	struct timeval tv;
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		cout << "Failed setsockopt for SO_RCVTIMEO: ";
		if (errno == EBADF) cout << "EBADF";
		else if (errno == EFAULT) cout << "EFAULT";
		else if (errno == EINVAL) cout << "EINVAL";
		else if (errno == ENOPROTOOPT) cout << "ENOPROTOOPT";
		else if (errno == ENOTSOCK) cout << "ENOTSOCK";
		else cout << "Unknown error";
		cout << endl;
		return false;
	}

	// Send SYN packet
	if (!send_tcp_packet(sock, srcip, srcport, ip, port, eTESTPACKET_SYN)) {
		cout << "Failed send syn packet" << endl;
		return false;
	}

	// Now wait for a response
	struct sockaddr_in saddr;
	socklen_t saddr_len = sizeof(saddr);
	char rcvbuf[2048];
	memset(rcvbuf, 0, 2048);
	int bufsz = recvfrom(sock, rcvbuf, 2048, 0, (struct sockaddr*)&saddr, &saddr_len);
	if (bufsz == -1) {
		if (errno == EAGAIN)
			cout << "Timed out" << endl;
		else
			cout << "Failed recvfrom()" << endl;
		return false;
	}

	if (bufsz == 0) {
		cout << "Nothing received." << endl;
		return false;
	}

	// Parse the response
	// NOTE!: response contains ip header as well for some reason...
	struct tcphdr* tcpresp = (struct tcphdr*)(rcvbuf + sizeof(struct iphdr));
	cout << "(" << bufsz << "B): ";
	parse_tcp_header(tcpresp);

	if (tcpresp->rst) {
		cout << "  Note: Received RST packet, which might not be followed by further responses!" << endl;
	}
	else if (tcpresp->syn && tcpresp->ack) {
		// Make sure to reset the connection to avoid getting blocked by SYN-flooding facilities
		if (!send_tcp_packet(sock, srcip, srcport, ip, port, eTESTPACKET_RST)) {
			cout << "Failed send RST packet" << endl;
			return false;
		}
	}

	return true;
}

// ********************************************************************************************************************

int main(int argc, char** argv)
{
	if (argc < 3) {
		print_help();
		return 1;
	}

	const char* host = argv[argc - 2];
	const unsigned short port = (unsigned short)atoi(argv[argc - 1]);
	unsigned short timeout = DEFAULT_TIMEOUT;
	bool repeat = DEFAULT_REPEAT;

	if (argc > 3) {
		int ihostarg = argc - 2;
		for (int iarg = 1; iarg < (argc - 2); ++iarg) {
			string arg = argv[iarg];
			if (arg == "-r" || arg == "--repeat") {
				repeat = true;
			}
			else if (arg == "-t" || arg == "--timeout") {
				if (iarg + 1 >= ihostarg) {
					cerr << "--timeout option requires one argument (timeout in seconds)" << endl;
					return 1;
				}

				timeout = atoi(argv[++iarg]);
			}
			else {
				cerr << arg << " is not a valid option!" << endl;
				return 1;
			}
		}
	}

	// Parse host
	uint32_t hostip = parse_host(host);
	REQUIRE(hostip != 0, "Invalid or unknown host given!");

	// Create socket
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	REQUIRE(sock != -1, "Failed socket()");

	// Determine source address of iface to default gateway
	struct ifreq irq;
	strncpy(irq.ifr_name, get_default_route_iface().c_str(), IFNAMSIZ - 1);
	irq.ifr_addr.sa_family = AF_INET;
	REQUIRE(ioctl(sock, SIOCGIFADDR, &irq) >= 0, "Could not get source ip address");

	uint32_t srcip = ((struct sockaddr_in*)&irq.ifr_addr)->sin_addr.s_addr;

	// Bind to a random port
	unsigned short srcport = bind_to_random_port(sock, srcip);
	REQUIRE(srcport != 0, "Could not bind to random port");

	bool success = false;
	while (true) {
		// Do the test
		auto start = chrono::system_clock::now();

		bool res = do_test(sock, hostip, port, srcip, srcport, timeout);
		if (res)
			success = true;

		if (!repeat)
			break;

		// Wait at least a second if there was a response immediately
		auto end = chrono::system_clock::now();
		chrono::duration<double> diff = end - start;
		if (diff.count() < 1.0)
			this_thread::sleep_for(chrono::duration<double>(1.0 - diff.count()));
	}

	close(sock);
	return (success ? 1 : 0);
}
