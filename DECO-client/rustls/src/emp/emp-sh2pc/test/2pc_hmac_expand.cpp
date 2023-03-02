#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;
using namespace std;
#include <algorithm>
#include <filesystem>
#include <bitset>
namespace fs = std::filesystem;

int port, party;
string file = fs::current_path() / "circuits/circuit_two_sha256_shared_states_shared_output.txt";
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

	bool in[1024];
	memset(in, false, 1024);

	bool in_a[768];
	memset(in_a, false, 768);

	bool out[256];
	memset(out, false, 256);

	// Input share
	string message_bin_le = argv[3];
	string share_state_ipad_bin = argv[4];
	string share_state_opad_bin = argv[5];

	if (message_bin_le.size() != 512) {
		cerr << "Message length not match!" << endl;
	}

	if (share_state_ipad_bin.size() != 256) {
		cerr << "State ipad length not match!" << endl;
	}

	if (share_state_opad_bin.size() != 256) {
		cerr << "State opad length not match!" << endl;
	}

    cout << "==== The content in in[] ====" << endl;
	for(int i = 0; i < 512; ++i) {
		in[i] = (message_bin_le[i] == '1');
		cout << in[i];
	}

	for(int i = 512; i < 768; ++i) {
		in[i] = (share_state_ipad_bin[i-512] == '1');
		cout << in[i];
	}

    for(int i = 768; i < 1024; ++i) {
		in[i] = (share_state_opad_bin[i-768] == '1');
		cout << in[i];
	}
	cout << endl;
	
	Integer a(768, in_a, ALICE);
	Integer b(1024, in, BOB);
	Integer c(256, out, PUBLIC);

	auto start = clock_start();
	cf.compute((block*)c.bits.data(), (block*)b.bits.data(), (block*)a.bits.data());
	string res = c.reveal<string>(BOB);
	cout << time_from(start)<<" "<<party<<" "<<res<<endl;

	ofstream ofs;
	string output_filename = argv[6];
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
	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE?nullptr:argv[7], port);

	setup_semi_honest(io, party);
	test(argv);
	
	finalize_semi_honest();
	delete io;
}
