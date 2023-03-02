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
	
	bool in[256];
	memset(in, false, 256);

	bool in_a[512];
	memset(in_a, false, 512);

	bool out[256];
	memset(out, false, 256);

	// Party 2
    string s1 = argv[3];
	string s1_bin = hex_to_binary(s1);
	while (s1_bin.size() != 256) {
		s1_bin = "0" + s1_bin;
	}
	reverse(begin(s1_bin), end(s1_bin));
	cout << "s1: " << s1 << endl;
	cout << "s1_bin after reverse: " << s1_bin << endl;

    cout << "==== The content in in [] ====" << endl;
    string input = s1_bin;
    for (int i = 0; i < 256; i++) {
        in[i] = (input[i] == '1');
		cout << in[i];
    }   
	cout << endl;

	Integer a(512, in_a, ALICE);
	Integer b(256, in, BOB);
	Integer c(256, out, PUBLIC);

	auto start = clock_start();
	cf.compute((block*)c.bits.data(), (block*)b.bits.data(), (block*)a.bits.data());
	string res = c.reveal<string>(BOB);
	cout << time_from(start)<<" "<<party<<" "<<res<<endl;

	ofstream ofs;
	string output_filename = argv[4];
	ofs.open(fs::current_path() / "2pc_hmac" / output_filename);
	if (!ofs.is_open()) {
		cout << "Failed to open file" << endl;
	}
	else {
		ofs << res;
		ofs.close();
	}
}

int main(int argc, char** argv) {
	
	cout << "argv" << endl;
	for (int i = 0; i < 6; i++) {
		cout << argv[i] << endl;
	}

	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE?nullptr:argv[5], port);

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
