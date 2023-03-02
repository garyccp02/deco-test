#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;
using namespace std;
#include <algorithm>
#include <filesystem>
#include <bitset>
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

	bool in[768];
	memset(in, false, 768);

	bool in_a[512];
	memset(in_a, false, 512);

	bool out[256];
	memset(out, false, 256);

	// ====== s1 ======
    cout << "==== The s1 ====" << endl;
    string s1 = argv[3];
	cout << "s1: " << s1 << endl;
    string s1_bin = hex_to_binary(s1);
    cout << s1_bin << endl;
    cout << "==== The s1 after reverse ====" << endl;
    reverse(begin(s1_bin), end(s1_bin));
    cout << s1_bin << endl;

	stringstream ss;

	// The input constant 1
    // [ H0: 2335507740,H1: 2200227439,H2: 3546272834,H3: 83913483,
    // H4: 301355998,H5: 2266431524,H6: 1402092146,H7: 439257589 ]
    vector<string> input_vec_1 = {"2335507740", "2200227439", "3546272834", "83913483", "301355998", "2266431524", "1402092146", "439257589"};

    // The input constant 2
    // [ H0: 582556975, H1: 2818161237, H2: 3127925320, H3: 2797531207,
    // H4: 4122647441, H5: 3290806166, H6: 3682628262, H7: 2419579842 ]   
	vector<string> input_vec_2 = {"582556975", "2818161237", "3127925320", "2797531207", "4122647441", "3290806166", "3682628262", "2419579842"};

    vector<string> input_vec = input_vec_1;
    input_vec.insert(end(input_vec), begin(input_vec_2), end(input_vec_2));

	vector<string> input_vec_bin = {};

	// Convert input to binary.
	cout << "The inputs:" << endl;
	for (int i = 0; i < input_vec.size(); i++) {
        if (i == 0) cout << "==== 1st constant ====" << endl;
        if (i == 8) cout << "==== 2nd constant ====" << endl;
		ss << hex << stol(input_vec[i]);
		string temp = hex_to_binary(ss.str());
		// reverse(begin(temp), end(temp));
		while (temp.length() < 32) temp = "0" + temp;
		input_vec_bin.push_back(temp);
		ss.str(string());
		cout << input_vec[i] << ":\t" << temp << endl;
	}

	string input_256_1 = "";
    string input_256_2 = "";
	for (int i = 0; i < input_vec_bin.size()-8; i++) {
		input_256_1 = input_256_1 + input_vec_bin[i];
	}
    for (int i = 8; i < input_vec_bin.size(); i++) {
		input_256_2 = input_256_2 + input_vec_bin[i];
	}
    reverse(begin(input_256_1), end(input_256_1));
    reverse(begin(input_256_2), end(input_256_2));
    cout << "==== 1st constant after reverse ====" << endl;
    cout << input_256_1 << endl;
    cout << "==== 2nd constant after reverse ====" << endl;
    cout << input_256_2 << endl;

	cout << "==== The content in in [] ====" << endl;
    for (int i = 0; i < 256; i++) {
        in[i] = (s1_bin[i] == '1');
        cout << in[i];
    }
    cout << endl;
    for (int i = 256; i < 512; i++) {
        in[i] = (input_256_1[i - 256] == '1');
        cout << in[i];
    }
    cout << endl;
    for (int i = 512; i < 768; i++) {
        in[i] = (input_256_2[i - 512] == '1');
        cout << in[i];
    }
    cout << endl;

	
	Integer a(512, in_a, ALICE);
	Integer b(768, in, BOB);
	Integer c(256, out, PUBLIC);

	auto start = clock_start();	
	cf.compute((block*)c.bits.data(), (block*)b.bits.data(), (block*)a.bits.data());
	string res = c.reveal<string>(BOB);
	cout << time_from(start)<<" "<<party<<" "<<res<<endl;

	ofstream ofs;
	ofs.open(fs::current_path() / "2pc_hmac/msg_client_share_le.txt");
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
	NetIO* io = new NetIO(party==ALICE?nullptr:argv[4], port);

	setup_semi_honest(io, party);
	test(argv);
	
	finalize_semi_honest();
	delete io;
}
