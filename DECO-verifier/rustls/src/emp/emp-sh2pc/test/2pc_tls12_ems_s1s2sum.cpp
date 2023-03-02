#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;
using namespace std;
#include <algorithm>
#include <filesystem>
#include <bitset>
#include <string>
namespace fs = std::filesystem;

int port, party;
string file = fs::current_path() / "circuits/tls12_ems_s1s2sum.txt";
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

	bool in_b[256];
	memset(in_b, false, 256);

	bool out[256];
	memset(out, false, 256);

	// Input share
	string s2 = argv[3];
	string s2_bin = hex_to_binary(s2);
	while (s2_bin.size() != 256) {
		s2_bin = s2_bin + "0";
	}
	reverse(begin(s2_bin), end(s2_bin));
	cout << "s2: " << s2 << endl;
	cout << "s2_bin after reverse: " << s2_bin << endl;

    string input = s2_bin;

 	for(int i = 0; i < 256; ++i) {
		in[i] = (input[i] == '1');
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
	Integer b(256, in_b, BOB);
	Integer c(256, out, PUBLIC);

	auto start = clock_start();
	cf.compute((block*)c.bits.data(), (block*)b.bits.data(), (block*)a.bits.data());
	cout << time_from(start)<<" "<<party<<" "<<c.reveal<string>(BOB)<<endl;

	ofstream ofs;
	string output_filename = argv[4];
	ofs.open(fs::current_path() / "2pc_hmac" / output_filename);
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
	NetIO* io = new NetIO(party==ALICE?nullptr:argv[5], port);

	cout << "argv" << endl;
	for (int i = 0; i < 6; i++) {
		cout << argv[i] << endl;
	}

	cout << "verifier ip: " << argv[5] << endl;
	cout << "port: " << port << endl;
	cout << "party: " << party << endl;

	cout << "before setup_semi_honest" << endl;
	setup_semi_honest(io, party);
	cout << "before test" << endl;
	test(argv);
	
	finalize_semi_honest();
	delete io;
}