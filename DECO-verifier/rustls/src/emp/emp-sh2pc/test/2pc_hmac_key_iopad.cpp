#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;
using namespace std;
#include <algorithm>
#include <filesystem>
#include <bitset>
namespace fs = std::filesystem;

int port, party;
string file = fs::current_path() / "circuits/circuit_2pc_hmac_key_iopad_self_IV_shared_shared.txt";
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

	bool in_b[512];
	memset(in_b, false, 512);

	bool out[256];
	memset(out, false, 256);

	stringstream ss;
	// Input share
	string share_bin = argv[3];
	// string share_bin = hex_to_binary(share_hex);

    // Deafult IV
	// 1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225
	vector<string> input_vec = {"1779033703", "3144134277", "1013904242", "2773480762", "1359893119", "2600822924", "528734635", "1541459225"};

	// Convert input to binary.
	vector<string> input_vec_bin = {};
	cout << "The inputs:" << endl;
	for (int i = 0; i < input_vec.size(); i++) {

		ss << hex << stol(input_vec[i]);
		string temp = hex_to_binary(ss.str());
		// reverse(begin(temp), end(temp));
		while (temp.length() < 32) temp = "0" + temp;
		input_vec_bin.push_back(temp);
		ss.str(string());
		cout << input_vec[i] << ":\t" << input_vec_bin[i] << endl;
	}

	string iv_str = "";
	for (int i = 0; i < input_vec_bin.size(); i++) {
		iv_str = iv_str + input_vec_bin[i];
	}
	// cout << iv_str << endl;
	reverse(begin(iv_str), end(iv_str));

    string input = share_bin + iv_str;

 	for(int i = 0; i < 768; ++i) {
		in[i] = (input[i] == '1');
	}

	// ====== The random share ======
    cout << "====== The random share ======" << endl;
    srand(time(NULL));
    for (int i = 768; i < 1024; i++) {
        int x = rand() % 2;
        in[i] = (x == 1);
        cout << in[i];
    }
    cout << endl;

	Integer a(1024, in, ALICE);
	Integer b(512, in_b, BOB);
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
		for(int i = 768; i < 1024; ++i) {
			ofs << in[i];
		}
		ofs.close();
	}
}

int main(int argc, char** argv) {
	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE?nullptr:argv[5], port);

	setup_semi_honest(io, party);
	test(argv);
	
	finalize_semi_honest();
	delete io;
}
