#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;
using namespace std;
#include <algorithm>
#include <filesystem>
#include <bitset>
#include <string>
namespace fs = std::filesystem;

int port, party;
string file = fs::current_path() / "circuits/circuit_2pc_hmac_shared_msg.txt";
BristolFormat cf(file.c_str());

inline const char* hex_char_to_bin(char c) {
	switch(toupper(c)) {
		case '0': return "0000";
		case '1': return "0001";
		case '2': return "0010";
		case '3': return "0011";
		case '4': return "0100";
		case '5': return "0101";
		case '6': return "0110";
		case '7': return "0111";
		case '8': return "1000";
		case '9': return "1001";
		case 'A': return "1010";
		case 'B': return "1011";
		case 'C': return "1100";
		case 'D': return "1101";
		case 'E': return "1110";
		case 'F': return "1111";
		default: return "0";
	}
}

inline std::string hex_to_binary(std::string hex) {
	std::string bin;
	for(unsigned i = 0; i != hex.length(); ++i)
		bin += hex_char_to_bin(hex[i]);
	return bin;
}

void test(char** argv) {

	bool in[512];
	memset(in, false, 512);

	bool in_b[768];
	memset(in_b, false, 768);

	bool out[256];
	memset(out, false, 256);

	// ====== s2 ======
    cout << "====== The s2 ======" << endl;
	string s2 = argv[3];
	cout << "s2: " << argv[3] << endl;
    string s2_bin = hex_to_binary(s2);
    cout << "s2_bin: " << s2_bin << endl;
	cout << "====== The s2 after reverse ======" << endl;
    reverse(begin(s2_bin), end(s2_bin));
    cout << "s2_bin: " << s2_bin << endl;
    for (int i = 0; i < 256; i++) {
        in[i] = (s2_bin[i] == '1');
    }

    // ====== The random share ======
    cout << "====== The random share ======" << endl;
    srand(time(NULL));
    for (int i = 256; i < 512; i++) {
        int x = rand() % 2;
        in[i] = (x == 1);
        cout << in[i];
    }
    cout << endl;

	
	Integer a(512, in, ALICE);
	Integer b(768, in_b, BOB);
	Integer c(256, out, PUBLIC);
	
	auto start = clock_start();
	cf.compute((block*)c.bits.data(), (block*)b.bits.data(), (block*)a.bits.data());
	cout << time_from(start)<<" "<<party<<" "<<c.reveal<string>(BOB)<<endl;

	// ====== Output the random share ======
	ofstream ofs;
	ofs.open(fs::current_path() / "2pc_hmac/msg_verifier_share_le.txt");
	if (!ofs.is_open()) {
		cout << "Failed to open file" << endl;
	}
	else {
		for(int i = 256; i < 512; ++i) {
			ofs << in[i];
		}
		ofs.close();
	}
}

int main(int argc, char** argv) {
	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE?nullptr:argv[4], port);

	setup_semi_honest(io, party);
	test(argv);
	
	finalize_semi_honest();
	delete io;
}
