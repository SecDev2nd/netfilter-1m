
#include <cstdlib>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <sstream>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <signal.h>

#include <map>
#include <fstream>
#include <vector>
#include <chrono>

#include "Trie.h"

void signalHandler(int signum);
void usage();
void printWarn();
void setTables();
void free_iptable();
void dump(unsigned char *buf, int size);

static u_int32_t print_pkt(struct nfq_data *tb);
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
			  struct nfq_data *nfa, void *data);

char host[100];

Trie trie;

void signalHandler(int signum)
{

	free_iptable();
	// 프로그램 종료
	exit(signum);
}

void printWarn()
{
	printf("Catch Forbidden Site\n");
	printf(" _____   ____    ____      __    __   ____  ____   ____   ____  ____    ____ \n");
	printf("|     | |    \\  |    |    |  |__|  | /    ||    \\ |    \\ |    ||    \\  /    |\n");
	printf("|   __| |  o  )  |  |     |  |  |  ||  o  ||  D  )|  _  | |  | |  _  ||   __|\n");
	printf("|  |_   |     |  |  |     |  |  |  ||     ||    / |  |  | |  | |  |  ||  |  |\n");
	printf("|   _]  |  O  |  |  |     |  `  '  ||  _  ||    \\ |  |  | |  | |  |  ||  |_ |\n");
	printf("|  |    |     |  |  |      \\      / |  |  ||  .  \\|  |  | |  | |  |  ||     |\n");
	printf("|__|    |_____| |____|      \\_/\\_/  |__|__||__|\\_||__|__||____||__|__||___,_|\n");
	printf("                                                                           \n");
}
void usage()
{
	printf("syntax : ./1m-block <file>\n");
	printf("sample : ./1m-block top-1m.csv\n");
}

// iptable사전 세팅 함수
void setTables()
{
	system("sudo iptables -F");
	system("sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0");
	system("sudo iptables -A INPUT -j NFQUEUE --queue-num 0");
	printf("Set Rules\n");
}

// iptable free
void free_iptable()
{
	system("sudo iptables -D OUTPUT -j NFQUEUE --queue-num 0");
	system("sudo iptables -D INPUT -j NFQUEUE --queue-num 0");
	printf("\nDelete Rules\n");
}

void dump(unsigned char *buf, int size)
{
	int i;
	for (i = 0; i < size; i++)
	{
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

void extracting(unsigned char *data)
{
    const struct iphdr *ip = (const struct iphdr *)data;
    //TCP check
    if (ip->protocol != IPPROTO_TCP)
    {
        return;
    }
    const struct tcphdr *tcp = (struct tcphdr *)(data + ip->ihl * 4);
    // if (tcp->th_dport != htons(80))
    // {
    //     return;
    // } 
    const char *http_payload = (char *)(data + ip->ihl * 4 + tcp->doff * 4);
    

    const char *host_header = strstr(http_payload, "Host: ");
    if (host_header)
    {
        host_header += 6;
        const char *end_of_line = strchr(host_header, '\r');
        if (end_of_line)
        {
            size_t hostname_length = end_of_line - host_header;
			strncpy(host, host_header, hostname_length);
			host[hostname_length] = '\0';
			printf("host : %s\n", host);
        }
    }
}

void saveData_trie(const std::string &filename)
{
	// CSV 파일 오픈
	std::ifstream file(filename);
	if (!file.is_open())
	{
		std::cerr << "Failed to open file: " << filename << std::endl;
		return;
	}

	std::string line;
	while (getline(file, line))
	{
		std::stringstream ss(line);
		std::string token;
		std::vector<std::string> tokens;
		while (std::getline(ss, token, ','))
		{
			tokens.push_back(token);
		}
		if (tokens.size() >= 2)
		{
			std::string value = tokens[1]; // 두 번째 열을 값으로 사용
			trie.insert(value);
		}
	}

	// 파일 닫기
	file.close();
}


bool measureSearchTime(Trie* forbidden_site)
{
    auto start = std::chrono::high_resolution_clock::now(); // 함수 실행 시작 시간 측정
    auto it = forbidden_site->find(host); // 요소 검색
    auto end = std::chrono::high_resolution_clock::now(); // 검색 완료 후 시간 측정
    std::chrono::duration<double> diff = end - start; // 실행 시간 계산
	std::cout << "Search time: " << diff.count() << " s\n";

	return it;
}

/* returns packet id */
static u_int32_t print_pkt(struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark, ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph)
	{
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			   ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph)
	{
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen - 1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen - 1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);
	ret = nfq_get_payload(tb, &data);
	printf("\n");

	if (ret >= 0)
	{
		//dump(data, ret);
		extracting(data);
		printf("payload_len=%d\n", ret);
		printf("\n");
	}
	fputc('\n', stdout);
	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *,
			  struct nfq_data *nfa, void *data)
{
	// Trie *trie = static_cast<Trie*>(data);
	std::string str(host, strlen(host));
	u_int32_t id = print_pkt(nfa);
	if (trie.find(str))
	{
		printWarn();
		std::memset(host, 0, strlen(host)); // host 배열 초기화
		sleep(1);
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	printf("entering callback\n");
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		usage();
		return -1;
	}
	signal(SIGINT, signalHandler);
	char *file_name = argv[1];
	Trie forbidden_site_trie;

	auto start = std::chrono::high_resolution_clock::now();
	saveData_trie(file_name);
	auto end = std::chrono::high_resolution_clock::now();

	std::chrono::duration<double> diff = end - start;
	std::cout << "Time to run saveData: " << diff.count() << " s\n";


	//trie.printAll();
	struct nfq_handle *h;

	struct nfq_q_handle *qh;

	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));

	setTables();

	printf("opening library handle\n");
	h = nfq_open();
	if (!h)
	{
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	/*
	필터링 큐 생성
	h : 핸들
	num : 생성할 큐의 번호,보통 0부터해서 순차 증가
	cb : 콜백함수의 포인터
	NULL(data) : 콜백함수에 전달될 데이터
	*/
	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &cb, &forbidden_site_trie);
	if (!qh)
	{
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}
	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}
	fd = nfq_fd(h);

	for (;;)
	{
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
		{
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		else
		{
			printf("recv failed\n");
		}

		if (rv < 0 && errno == ENOBUFS)
		{
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);
	free_iptable();
	exit(0);
}
