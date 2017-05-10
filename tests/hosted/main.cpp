/* Copyright (C) 2017 Eugene Hutorny <eugene@hutorny.in.ua>
 *
 * main.cpp - Command line interface for Chaskey Block Cipher
 * invented by Nicky Mouha http://mouha.be/chaskey/
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * https://opensource.org/licenses/MIT
 */

#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <unistd.h>
#include <stdint.h>
#include <ctime>

#include "chaskey.h"
#include "chaskey.hpp"
#include "miculog.hpp"

using namespace std;

enum class operation {
	help,
	sign,
	verify,
	encrypt,
	decrypt,
	test,
	bench,
	masters,
};

enum exitcode {
	success,
	err_test,
	err_veify,
	bad_args,
	ioerror,
	exit_help,
	aborted
};

struct options {
	const char* keyfile;
	const char* key;
	const char* textfile;
	const char* plaintext;
	const char* digest;
	const char* nonce;
	const char* iv;
	operation oper;
	bool hexout;
	bool hexkey;
	unsigned long param;
};

static int verbosity = 1;

class error : public exception {
public:
	error(const string& message) noexcept : msg(message) {}
	const char* what() const noexcept { return msg.c_str(); }
private:
	const string msg;
};

void fillopts(int argc, char * const argv[], options& opts) throw(error) {
	char c;
	while(-1 != (c = getopt(argc, argv, "edsm:V:N:tT:b:k:K:i:I:X:hvq")) ) {
		switch(c) {
		case 'e': opts.oper = operation::encrypt; break;
		case 'N': opts.nonce = optarg; break;
		case 'V': opts.iv = optarg; break;
		case 'd': opts.oper = operation::decrypt; break;
		case 's': opts.oper = operation::sign; break;
		case 'm': opts.oper = operation::verify; opts.digest = optarg; break;
		case 't': opts.oper = operation::test; break;
		case 'k': opts.keyfile = optarg; opts.key = nullptr; break;
		case 'X': opts.key = optarg; opts.keyfile = nullptr; opts.hexkey = true; break;
		case 'K': opts.key = optarg; opts.keyfile = nullptr; opts.hexkey = false; break;
		case 'i': opts.textfile = optarg; opts.plaintext = nullptr; break;
		case 'I': opts.plaintext = optarg; opts.textfile = nullptr; break;
		case 'h': opts.hexout = true;  break;
		case 'v': verbosity = 2;  break;
		case 'q': verbosity = 0;  break;
		case '?': opts.oper = operation::help; break;
		case 'T': opts.oper = operation::masters; opts.param = strtol(optarg,nullptr, 10);	break;
		case 'b': opts.oper = operation::bench;	opts.param = strtol(optarg,nullptr, 10); break;
		default:
			throw error(string("Unrecognized option '") + c + "'");
		}
	}
}

static inline uint32_t hex(char c) throw(error) {
	if( c >= '0' && c <= '9' ) return c-'0';
	if( c >= 'A' && c <= 'F' ) return c-'A' +0xA;
	if( c >= 'a' && c <= 'f' ) return c-'a' +0xa;
	throw error(string("Invalid hex character '") + c + "'");
}

static inline uint32_t hex(const char * str) throw(error) {
	return hex(str[1]) | (hex(str[0]) << 4);
}

using namespace crypto;
using namespace chaskey;
static constexpr block_t default_key {
		0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210
};

ostream& operator<<(ostream& o, const block_t& k) {
	return o << '{' << hex << k[0] << ',' << k[1] << ',' << k[2] << ',' << k[3] << '}';
}

void hex2block(const char* str, block_t& key) throw(error) {
	if( 128 != (strlen(str) * 4) )
		throw error(string("Invalid hex key :'") + str + "', expected 32 hex digits");
	for(int i = 0; i <16; ++i, str+=2) {
		key[i/4] |= hex(str) << (8*(i%4));
	}
}

bool getkeys(const options& opts, block_t& key, block_t& iv) throw(error) {
	if( opts.keyfile ) {
		ifstream file(opts.keyfile, fstream::in | fstream::binary);
		if( ! file ) {
			throw error(string("Error accessing key file '") + opts.keyfile + "'");
		}
		file.read(reinterpret_cast<char*>(&key[0]), sizeof(block_t));
		if( ! file ) {
			throw error(string("Error reading key file '") + opts.keyfile + "'");
		}
		return true;
	}
	for(auto& k : key) k = 0;
	if( opts.key ) {
		if( opts.hexkey ) {
			hex2block(opts.key, key);
		} else {
			if( 128 != (strlen(opts.key) * 8) )
				throw error(string("Invalid key '") + opts.key + "', expected 16 characters");
			for(int i = 0; i < 16; ++i) {
				key[i/4] |= static_cast<uint32_t>(opts.key[i]) << ((i%4)*8);
			}
		}
		return true;
	}
	if( opts.iv ) {
		hex2block(opts.iv, iv);
	}

	for(int i=0; i<4; ++i) key[i] = default_key[i];
	return false;
}

istream& input(const options& opts) {
	static istringstream str;
	static fstream file;
	if(opts.plaintext) {
		str.str(opts.plaintext);
		return str;
	}
	if( opts.textfile ) {
		file.open(opts.textfile, fstream::in | fstream::binary );
		if( ! file.good() )
			cerr << "Error opening file '" << opts.textfile << "'" << endl;
		return file;
	}
	return cin;
}

struct hexwrapper {
	ostream& out;
	void write(const char* data, size_t len) {
		while(len--) {
			out << hex << setw(2) << setfill('0') << unsigned(*data++);
		}
	}
};

int sign(istream& in, const block_t& key, bool hexout) {
	crypto::chaskey::Cipher8::Mac mac(key);
	while(in) {
		char plaintext[sizeof(block_t)];
		size_t len = in.read(plaintext,sizeof(plaintext)).gcount();
		mac.update((const uint8_t*)plaintext, len, in.eof());
	}
	if( hexout ) {
		mac.write(hexwrapper{cout});
		cout << endl;
	} else
		mac.write(cout);
	return success;
}

int verify(istream& in, const block_t& key, const block_t& signature) {
	crypto::chaskey::Cipher8::Mac mac(key);
	while(in) {
		char plaintext[sizeof(block_t)];
		size_t len = in.read(plaintext,sizeof(plaintext)).gcount();
		mac.update((const uint8_t*)plaintext, len, in.eof());
	}
	return mac.verify(signature) ? success : err_veify;
}

int encrypt(istream& in, const block_t& key, const char* nonce, const block_t& iv) {
	crypto::chaskey::Cipher8::Cbc cbc(key);
	if( nonce )
		cbc.init(nonce, strlen(nonce));
	else
		cbc.init(iv);
	while(in) {
		char plaintext[sizeof(block_t)];
		size_t len = in.read(plaintext,sizeof(plaintext)).gcount();
		cbc.encrypt(cout, (const uint8_t*)plaintext, len, in.eof());
	}
	return success;
}

int decrypt(istream& in, const block_t& key, const char* nonce, const block_t& iv) {
	crypto::chaskey::Cipher8::Cbc cbc(key);
	if( nonce )
		cbc.init(nonce, strlen(nonce));
	else
		cbc.init(iv);
	while(in) {
		char ciphertext[sizeof(block_t)];
		size_t len = in.read(ciphertext,sizeof(ciphertext)).gcount();
		cbc.decrypt(cout, (const uint8_t*)ciphertext, len);
	}
	return success;
}


int help() {
	cerr << "Usage: chaskey <operation> [options]" << endl
		 << "  <operation> is one of the following:" << endl
		 << "  -s     : sign message" << endl
		 << "  -m <x> : verify message signature <x>" << endl
		 << "  -e     : encrypt message" << endl
		 << "  -d     : decrypt message" << endl
		 << "  -t     : self-test" << endl
		 << "  [options] are :" << endl
		 << "  -I <m> : use message <m>" << endl
		 << "  -i <f> : read message from file <f>" << endl
		 << "  -K <k> : set the key as byte string <k>" << endl
		 << "  -X <x> : set the key given as hexadecimal string <x>" << endl
		 << "  -N <n> : set the nonce as byte string <n>" << endl
		 << "  -V <x> : set the initialization vector as hexadecimal string <x>" << endl
		 << "  -k <f> : read key from file <f>" << endl
		 << "  -h     : write signature in hexadecimal" << endl
		 << "  -v     : set verbose mode" << endl
		 << "  -q     : set quite mode" << endl << endl
		 << "For example: " << endl
		 << "# chaskey -s -h -K secretkey16bytes -I Hello " << endl
		 << "# chaskey -e -N nonce12bytes -K secretkey16bytes -i Hello.txt " << endl;
	return exit_help;
}

extern bool test();
extern const block_t& get_test_vector(unsigned);
extern const uint8_t* get_test_message();
extern bool bench(unsigned long);

__attribute__((weak))
bool test() {	cerr << "Tests are not available" << endl;	return false; }

__attribute__((weak))
bool bench(unsigned) { cerr << "Benchmarking is not available" << endl;	return false; }
__attribute__((weak))
const block_t& get_test_vector(unsigned) {	return default_key; }
__attribute__((weak))
const uint8_t* get_test_message() {	return (const uint8_t*)("Plain text message"); }

unsigned long milliseconds() {
	return std::clock() / (CLOCKS_PER_SEC/1000);
}

const block_t iv { };


bool make_masters(int param) {
	if( param >= 64 ) return false;
	crypto::chaskey::Chaskey8::Cbc cbc(get_test_vector(param));
	cbc.init(iv);
	cbc.encrypt(cout, get_test_message(), param, true);
	return true;
}


int main(int argc, char * const argv[]) {
	options opts = {};
	block_t key, iv {};
	opts.hexout = isatty(fileno(stdin));
	try {
	if(argc < 1 && isatty(fileno(stdin)) )
	    cerr << "Processing stdin to stdout with a default key" << endl;
	else
		fillopts(argc, argv, opts);

	/* operations that require no key									*/
	switch(opts.oper) {
	case operation::help: 	return ! help();
	case operation::test: 	return ! test();
	case operation::bench: 	return ! bench(opts.param);
	case operation::masters:return ! make_masters(opts.param);
	default:;
	}
	if( ! getkeys(opts, key, iv) ) {
		if( verbosity > 1 || (verbosity == 1 && isatty(fileno(stdin))) )
		    cerr << "Using default key " << key << endl;
	};

	if( (opts.oper == operation::encrypt || opts.oper == operation::decrypt) &&
		! opts.nonce && ! opts.iv ) {
		if( verbosity > 1 || (verbosity == 1 && isatty(fileno(stdin))) )
		    cerr << "Using default iv " << iv << endl;
	}
	istream& in = input(opts);
	if( ! in ) return ioerror;
	switch(opts.oper) {
	case operation::sign:
		return sign(in, key, opts.hexout);
	case operation::verify: {
		block_t block {};
		hex2block(opts.digest, block);
		int res = verify(in, key, block);
		if( verbosity > 1 && res == success )
			cerr << "Verified" << endl;
		if( verbosity >= 1 && res != success )
			cerr << "Not verified" << endl;
		return res;
		}
	case operation::encrypt:
		return encrypt(in, key, opts.nonce, iv);
	case operation::decrypt:
		return decrypt(in, key, opts.nonce, iv);
	default:;
		return bad_args;
	};
	if( isatty(fileno(stderr)))
		cerr << endl;
	} catch(const error& e) {
		if( verbosity >= 1 )
			cerr << e.what() << endl;
		return bad_args;
	} catch(const exception& e) {
		if( verbosity >= 1 )
			cerr << e.what() << endl;
		return ioerror;
	} catch(...) {
		if( verbosity >= 1 )
			cerr << "Aborted" << endl;
		return aborted;
	}
}

void LogAppender::log(miculog::level lvl, const char* fmt, ...) noexcept {
	using typename miculog::level;
	FILE* file = stderr;
	switch( lvl ) {
	case level::fail:
		if( verbosity < 1 ) return;
		fprintf(file, "FAILED\t:");
		break;
	case level::error:
		if( verbosity < 2 ) return;
		fprintf(file, "error\t:");
		break;
	case level::warn:
		file = stdout;
		break;
	case level::info:
		file = stdout;
		if( verbosity < 1 ) return;
		break;
	default:
		return;
	}
	va_list args;
	va_start(args, fmt);
	vfprintf(file, fmt, args);
	va_end(args);
}



