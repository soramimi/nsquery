#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <vector>
#include <map>

#define stricmp(A, B) strcasecmp(A, B)

void encode_netbios_name(char const *name, std::vector<uint8_t> *out)
{
	out->clear();
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
		out->push_back(a);
		out->push_back(b);
	}
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

static int getname(char const *buf, char const *end, int pos, std::string *out)
{
	while (buf + pos < end) {
		int n = (uint8_t)buf[pos];
		pos++;
		if (n == 0) break;
		if ((n & 0xc0) == 0xc0) {
			n = (n & 0x3f) | (uint8_t)buf[pos];
			pos++;
			getname(buf, end, n, out);
			break;
		}
		if (!out->empty()) {
			*out += '.';
		}
		*out += std::string(buf + pos, n);
		pos += n;
	}
	return pos;
}

int main()
{
	enum Mode {
		DNS,
		MDNS,
		WINS,
		LLMNR,
	};

//	Mode mode = DNS;
//	std::string name = "www.twitter.com";

	Mode mode = MDNS;
	std::string name = "aimeq-p-31.local";

//	Mode mode = WINS;
//	std::string name = "nas";

//	Mode mode = LLMNR;
//	std::string name = "julia";

	bool multicast = false;

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
	if (mode == WINS) {
		int yes = 1;
		addr.sin_port = htons(137);
		addr.sin_addr.s_addr = INADDR_BROADCAST;
		setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char *)&yes, sizeof(yes));
	} else if (mode == LLMNR) {
		addr.sin_port = htons(5355);
		addr.sin_addr.s_addr = INADDR_ANY;
		multicast = true;
	} else if (mode == MDNS) {
		addr.sin_port = htons(5353);
		addr.sin_addr.s_addr = INADDR_ANY;
		multicast = true;
	} else if (mode == DNS) {
		addr.sin_port = htons(53);
		addr.sin_addr.s_addr = htonl(0x08080808); // 8.8.8.8
	}
	bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	// 問い合わせパケットを送信
	{
		size_t pos;
		auto Write16 = [&](uint16_t v){
			buf[pos++] = v >> 8;
			buf[pos++] = v & 255;
		};

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
		pos = 6 * 2;
		{
			std::vector<uint8_t> namebytes;
			if (mode == WINS) {
				encode_netbios_name(name.c_str(), &namebytes);
			} else {
				char const *p = name.c_str();
				namebytes.assign(p, p + name.size());
			}
			uint8_t const *src = namebytes.data();
			uint8_t const *end = src + namebytes.size();
			int n = 0;
			while (1) {
				int c = 0;
				if (src + n < end) {
					c = (unsigned char)src[n];
				}
				if (c == '.' || c == 0) {
					buf[pos++] = n;
					memcpy(buf + pos, src, n);
					pos += n;
					src += n;
					if (c == 0) {
						buf[pos++] = 0;
						break;
					}
					src++;
					n = 0;
				} else {
					n++;
				}
			}
		}
		if (mode == WINS) {
			Write16(0x0020); // Type: NB
		} else {
			Write16(0x0001); // Type: A
		}
		Write16(0x0001); // Class: IN

		if (mode == MDNS) {
			addr.sin_addr.s_addr = htonl(0xe00000fb); // 224.0.0.251
		} else if (mode == LLMNR) {
			addr.sin_addr.s_addr = htonl(0xe00000fc); // 224.0.0.252
		}
		sendto(sock, buf, pos, 0, (struct sockaddr *)&addr, sizeof(addr));
	}
	// 応答パケットを受信
	if (multicast) {
		struct ip_mreq mreq = {};
		mreq.imr_interface.s_addr = INADDR_ANY;
		mreq.imr_multiaddr.s_addr = htonl(0xe00000fb); // 224.0.0.251
		setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq));
	}
	{
		memset(buf, 0, sizeof(buf));
		// recvfrom()を利用してUDPソケットからデータを受信
		addrlen = sizeof(senderinfo);
		len = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&senderinfo, &addrlen);
		// 送信元に関する情報を表示
		inet_ntop(AF_INET, &senderinfo.sin_addr, senderstr, sizeof(senderstr));
		printf("recvfrom : %s, port=%d, length=%d\n", senderstr, ntohs(senderinfo.sin_port), len);
		if (len > 0) {
			struct Answer {
				std::string name;
				uint32_t addr;
				Answer() = default;
				Answer(std::string const &name, uint32_t addr)
					: name(name)
					, addr(addr)
				{
				}
			};

			std::vector<uint32_t> addrs;
			std::vector<Answer> answers;
			std::map<std::string, std::string> cnames;
			char const *end = buf + len;
			size_t pos;
			auto Read16 = [&](){
				uint8_t const *p = (uint8_t const *)(buf + pos);
				uint16_t v = (p[0] << 8) | p[1];
				pos += 2;
				return v;
			};
			auto Read32 = [&](){
				uint8_t const *p = (uint8_t const *)(buf + pos);
				uint32_t v = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
				pos += 4;
				return v;
			};
			uint16_t *p = (uint16_t *)buf;
			uint16_t id = ntohs(p[0]); // ID
			uint16_t flags = ntohs(p[1]); // flags
			uint16_t qdcount = ntohs(p[2]); // QDCOUNT
			uint16_t ancount = ntohs(p[3]); // ANCOUNT
			uint16_t nscount = ntohs(p[4]); // NSCOUNT
			uint16_t arcount = ntohs(p[5]); // ARCOUNT
			int i = 6 * 2;
			pos = 6 * 2;
			for (int j = 0; j < qdcount; j++) {
				std::string aname;
				pos = getname(buf, end, pos, &aname);
				Read16();
				Read16();
			}
			for (int a = 0; a < ancount; a++) {
				std::string aname;
				pos = getname(buf, end, pos, &aname);
				if (mode == WINS) {
					aname = decode_netbios_name(aname.c_str(), aname.size());
				}
				uint16_t type = Read16();
				uint16_t clas = Read16();
				uint32_t time = Read32();
				if (mode == WINS) {
					uint16_t dlen = Read16(); // data length
					if (dlen == 6) {
						while (pos + 5 < len) {
							Read16(); // flags
							uint32_t addr = Read32();
							answers.emplace_back(aname, addr);
						}
					}
				} else if (mode == LLMNR || mode == MDNS || mode == DNS) {
					if (type == 1 && clas == 1) {
						int n = Read16(); // data length
						if (n == 4) {
							uint32_t addr = Read32();
							answers.emplace_back(aname, addr);
						} else {
							pos += n;
						}
					} else if (type == 5 && clas == 1) { // CNAME
						int n = Read16(); // data length
						if (n == 2) {
							std::string cname;
							getname(buf, buf + pos + n, pos, &cname);
							cnames[aname] = cname;
						}
						pos += n;
					}
				}
			}

			auto it = cnames.find(name);
			if (it != cnames.end()) {
				name = it->second;
			}


			if (!answers.empty()) {
				for (int i = 0; i < answers.size(); i++) {
					Answer const &ans = answers[i];
					if (stricmp(ans.name.c_str(), name.c_str()) == 0) {
						addrs.push_back(ans.addr);
					}
				}
				for (uint32_t addr : addrs) {
					int a = (addr >> 24) & 255;
					int b = (addr >> 16) & 255;
					int c = (addr >> 8) & 255;
					int d = addr & 255;
					printf("%u.%u.%u.%u\n", a, b, c, d);
				}
			}

		}
	}
	close(sock);
	return 0;
}
