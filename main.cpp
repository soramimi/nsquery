#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vector>
#include <string>

#define stricmp(A, B) strcasecmp(A, B)

std::string encode_netbios_name(char const *name)
{
	std::vector<char> vec;
	vec.reserve(32);
	for (int i = 0; i < 16; i++) {
		int c = 0;
		if (i < 15) {
			c = toupper((uint8_t)*name);
			if (c) {
				name++;
			} else {
				c = ' ';
			}
		}
		int a = 'A' + (c >> 4);
		int b = 'A' + (c & 0x0f);
		vec.push_back(a);
		vec.push_back(b);
	}
	return vec.empty() ? std::string() : std::string(vec.data(), vec.size());
}

std::string decode_netbios_name(char const *bytes, int len)
{
	int n = len / 2;
	std::vector<char> vec;
	vec.reserve(n);
	for (int i = 0; i < len; i++) {
		char c = ((bytes[i * 2] - 'A') << 4) | ((bytes[i * 2 + 1] - 'A') & 0x0f);
		if (c == 0 || c == ' ') break;
		vec.push_back(c);
	}
	return vec.empty() ? std::string() : std::string(vec.data(), vec.size());
}

int main()
{
	const uint32_t timezone = 9 * 60 * 60; // +0900 JST

	enum Mode {
		WINS,
		LLMNR,
	};
	Mode mode = LLMNR;
	std::string name = "grace";

	int sock;
	struct sockaddr_in addr;
	struct sockaddr_in senderinfo;
	socklen_t addrlen;
	char buf[2048];
	char senderstr[16];
	int len;
	// AF_INET+SOCK_DGRAMなので、IPv4のUDPソケット
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	// 待ち受けポート番号を137にするためにbind()を行う
	addr.sin_family = AF_INET;
	int yes = 1;
	if (mode == WINS) {
		addr.sin_port = htons(137);
		addr.sin_addr.s_addr = INADDR_BROADCAST;
		setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char *)&yes, sizeof(yes));
	} else if (mode == LLMNR) {
		addr.sin_port = htons(5355);
		addr.sin_addr.s_addr = INADDR_ANY;
	}
	bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	// 問い合わせパケットを送信
	{
		std::string s;
		if (mode == WINS) {
			s = encode_netbios_name(name.c_str());
		} else {
			s = name;
		}

		memset(buf, 0, sizeof(buf));

		uint16_t id = 0x0001;

		uint16_t flags = 0x0110;

		uint16_t *p = (uint16_t *)buf;
		p[0] = htons(id); // ID
		p[1] = htons(flags); // flags
		p[2] = htons(1); // QDCOUNT
		p[3] = htons(0); // ANCOUNT
		p[4] = htons(0); // NSCOUNT
		p[5] = htons(0); // ARCOUNT
		size_t n = s.size();
		buf[12] = n;
		for (int i = 0; i < n; i++) {
			buf[13 + i] = s[i];
		}
		n += 13;
		buf[n++] = 0;
		auto WriteS = [&](uint16_t v){
			buf[n++] = v >> 8;
			buf[n++] = v & 255;
		};
		if (mode == WINS) {
			WriteS(0x0020); // Type: NB
		} else {
			WriteS(0x0001); // Type: A
		}
		WriteS(0x0001); // Class: IN

		if (mode == LLMNR) {
			addr.sin_addr.s_addr = htonl(0xe00000fc); // 224.0.0.252
		}
		sendto(sock, buf, n, 0, (struct sockaddr *)&addr, sizeof(addr));
	}
	// 応答パケットを受信
	{
		memset(buf, 0, sizeof(buf));
		// recvfrom()を利用してUDPソケットからデータを受信
		addrlen = sizeof(senderinfo);
		len = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&senderinfo, &addrlen);
		// 送信元に関する情報を表示
		inet_ntop(AF_INET, &senderinfo.sin_addr, senderstr, sizeof(senderstr));
		printf("recvfrom : %s, port=%d, length=%d\n", senderstr, ntohs(senderinfo.sin_port), len);
		if (len > 0) {
			std::vector<uint32_t> addrs;
			int pos;
			auto Read16 = [&](){
				uint8_t h = (uint8_t)buf[pos++];
				uint8_t l = (uint8_t)buf[pos++];
				return (h << 8) | l;
			};
			uint16_t *p = (uint16_t *)buf;
			uint16_t id = ntohs(p[0]); // ID
			uint16_t flags = ntohs(p[1]); // flags
			uint16_t qdcount = ntohs(p[2]); // QDCOUNT
			uint16_t ancount = ntohs(p[3]); // ANCOUNT
			uint16_t nscount = ntohs(p[4]); // NSCOUNT
			uint16_t arcount = ntohs(p[5]); // ARCOUNT
			int i = 6 * 2;
			for (int j = 0; j < qdcount; j++) {
				int n = (uint8_t)buf[i];
				if (n == 0) {
					i += 4;
				}
				i += n;
			}
			if (ancount == 1) {
				pos = 6 * 2;
				int n = (uint8_t)buf[pos];
				if (buf[pos + 1 + n] == 0) {
					std::string aname(buf + pos + 1, n);
					if (mode == WINS) {
						aname = decode_netbios_name(aname.c_str(), aname.size());
					}
					if (stricmp(aname.c_str(), name.c_str()) == 0) {
						pos += n + 2;
						uint16_t type = Read16();
						uint16_t clas = Read16();
						bool ok = false;
						if (mode == WINS) {
							ok = (type == 32 && clas == 1);
						} else if (mode == LLMNR) {
							ok = (type == 1 && clas == 1);
						}
						if (ok) {
							if (mode == WINS) {
								pos += 4; // skip time
								n = Read16(); // data length
								while (pos + 5 < len) {
									uint16_t flags2 = ntohs(*(uint16_t *)(buf + pos));
									uint32_t addr;
									memcpy(&addr, buf + pos + 2, 4);
									addr = ntohl(addr);
									addrs.push_back(addr);
									pos += 6;
								}
							} else if (mode == LLMNR) {
								while (1) {
									uint8_t n = buf[pos++];
									if (n == 0) break;
									pos += n;
								}
								uint16_t type = Read16();
								uint16_t clas = Read16();
								pos += 4; // skip time
								n = Read16(); // data length
								uint32_t addr;
								memcpy(&addr, buf + pos, 4);
								addr = ntohl(addr);
								addrs.push_back(addr);
								pos += 4;
							}
						}
					}
				}
			}


			if (!addrs.empty()) {
				uint32_t from = ntohl(senderinfo.sin_addr.s_addr);
				uint32_t addr = 0;
				uint32_t diff = 0;
				for (int i = 0; i < addrs.size(); i++) {
					uint32_t a = addrs[i];
					uint32_t d = (a > from) ? (a - from) : (from - a);
					if (i == 0 || diff > d) {
						addr = a;
						diff = d;
					}
				}
				int a = (addr >> 24) & 255;
				int b = (addr >> 16) & 255;
				int c = (addr >> 8) & 255;
				int d = addr & 255;
				printf("%u.%u.%u.%u\n", a, b, c, d);
			}

		}
	}
	close(sock);
	return 0;
}
