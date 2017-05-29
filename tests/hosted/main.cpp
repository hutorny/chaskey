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
#include <vector>

#include "chaskey.h"
#include "chaskey.hpp"
#include "miculog.hpp"

#ifdef WITH_AES128CLOC_TEST
extern "C" {
#	include <cloc.h>
}
#endif

using namespace std;

enum class operation {
	help,
	sign,
	verify,
	encrypt,
	decrypt,
	cloc,
	uncloc,
	test,
	bench,
	masters,
};

enum exitcode {
	success,
	err_test,
	err_verify,
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
	const char* ad;
	const char* adfile;
	const char* outfile;
	operation oper;
	bool hexout;
	bool hexkey;
	bool aes128cloc;
	bool tocerr;
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
	while(-1 != (c = getopt(argc, argv, "edsm:cu:o:V:N:tT:b:k:K:i:I:X:a:A:hvqr2"))){
		switch(c) {
		case 'e': opts.oper = operation::encrypt; break;
		case 'd': opts.oper = operation::decrypt; break;
		case 's': opts.oper = operation::sign; break;
		case 'm': opts.oper = operation::verify; opts.digest = optarg; break;
		case 't': opts.oper = operation::test; break;
		case 'c': opts.oper = operation::cloc; break;
		case 'u': opts.oper = operation::uncloc; opts.digest = optarg; break;
		case 'N': opts.nonce = optarg; break;
		case 'V': opts.iv = optarg; break;
		case 'k': opts.keyfile = optarg; opts.key = nullptr; break;
		case 'X': opts.key = optarg; opts.keyfile = nullptr; opts.hexkey = true; break;
		case 'K': opts.key = optarg; opts.keyfile = nullptr; opts.hexkey = false; break;
		case 'A': opts.ad = optarg; opts.adfile = nullptr; break;
		case 'a': opts.adfile = optarg; opts.ad = nullptr; break;
		case 'i': opts.textfile = optarg; opts.plaintext = nullptr; break;
		case 'I': opts.plaintext = optarg; opts.textfile = nullptr; break;
		case 'o': opts.outfile = optarg; break;
		case 'h': opts.hexout = true;  break;
		case '2': opts.tocerr = true;  break;
		case 'v': verbosity = 2;  break;
		case 'q': verbosity = 0;  break;
#		ifdef WITH_AES128CLOC_TEST
		case 'r': opts.aes128cloc = true;  break;
#		endif
		case '?': opts.oper = operation::help; break;
		case 'T': opts.oper = operation::masters; opts.param = strtol(optarg,nullptr, 10);	break;
		case 'b': opts.oper = operation::bench;	opts.param = strtol(optarg,nullptr, 10); break;
		default:
			throw error(string("Unrecognized option '") + c + "'");
		}
	}
}

static inline uint32_t hex(char c) throw(error) {
	if( c == 0 ) return 0;
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

static ostream& operator<<(ostream& o, const block_t& k) {
	return o << '{' << hex << k[0] << ',' << k[1] << ',' << k[2] << ',' << k[3] << '}';
}

static void hex2block(const char* str, block_t& key) throw(error) {
	if( ! str )
		throw error(string("Missing key, expected 32 hex digits"));
	if( 128 != (strlen(str) * 4) )
		throw error(string("Invalid hex key :'") + str + "', expected 32 hex digits");
	for(uint_fast8_t i = 0; i <16; ++i, str+=2) {
		key[i/4] |= hex(str) << (8*(i%4));
	}
}

static uint_fast8_t hex2bytes(const char* str, uint8_t* key, uint_fast8_t len) throw(error) {
	if( ! str )
		throw error(string("Missing byte string"));
	uint_fast8_t i;
	for(i = 0; i < len && *str; ++i, str+=2) {
		key[i] = hex(str);
		if( !  str[1] ) break;
	}
	return i;
}


static bool getkeys(const options& opts, block_t& key, block_t& iv) throw(error) {
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

static istream& input(const options& opts) {
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

static ostream& output(const options& opts) {
	static fstream file;
	if( opts.outfile ) {
		file.open(opts.outfile, fstream::out | fstream::binary );
		if( ! file.good() )
			cerr << "Error opening file '" << opts.outfile << "'" << endl;
		return file;
	}
	return cout;
}


static istream& adata(const options& opts) {
	static istringstream str;
	static fstream file;
	if(opts.ad) {
		str.str(opts.ad);
		return str;
	}
	if( opts.adfile) {
		file.open(opts.textfile, fstream::in | fstream::binary );
		if( ! file.good() )
			cerr << "Error opening file '" << opts.adfile << "'" << endl;
		return file;
	}
	str.str("");
	return str;
}


struct hexwrapper {
	ostream& out;
	void write(const char* data, size_t len) {
		while(len--) {
			out << hex << setw(2) << setfill('0') <<
					(static_cast<unsigned>(*data++) & 0xFF);
		}
	}
};

static int sign(istream& in, const block_t& key, bool hexout, bool tocerr) {
	crypto::chaskey::Cipher8::Mac mac(key);
	while(in) {
		char plaintext[sizeof(block_t)];
		size_t len = in.read(plaintext,sizeof(plaintext)).gcount();
		mac.update((const uint8_t*)plaintext, len, in.eof());
	}
	if( tocerr ) {
		mac.write(hexwrapper{cerr});
		cerr << endl;
	} else if( hexout ) {
		mac.write(hexwrapper{cout});
		cout << endl;
	} else
		mac.write(cout);
	return success;
}

static int verify(istream& in, const block_t& key, const uint8_t* signature, uint_fast8_t len) {
	crypto::chaskey::Cipher8::Mac mac(key);
	while(in) {
		char plaintext[sizeof(block_t)];
		size_t len = in.read(plaintext,sizeof(plaintext)).gcount();
		mac.update((const uint8_t*)plaintext, len, in.eof());
	}
	return mac.verify(signature, len) ? success : err_verify;
}

static int encrypt(istream& in, ostream& out,
		const block_t& key, const char* nonce, const block_t& iv) {
	crypto::chaskey::Cipher8::Cbc cbc(key);
	if( nonce )
		cbc.init(nonce, strlen(nonce));
	else
		cbc.init(iv);
	while(in) {
		char plaintext[sizeof(block_t)];
		size_t len = in.read(plaintext,sizeof(plaintext)).gcount();
		cbc.encrypt(out, (const uint8_t*)plaintext, len, in.peek() == EOF);
	}
	return success;
}

static int decrypt(istream& in, ostream& out,
	const block_t& key, const char* nonce, const block_t& iv) {
	crypto::chaskey::Cipher8::Cbc cbc(key);
	if( nonce )
		cbc.init(nonce, strlen(nonce));
	else
		cbc.init(iv);
	while(in) {
		char ciphertext[sizeof(block_t)];
		size_t len = in.read(ciphertext,sizeof(ciphertext)).gcount();
		cbc.decrypt(out, (const uint8_t*)ciphertext, len);
	}
	return success;
}

byte frominput[sizeof(block)] {};

#ifdef WITH_AES128CLOC_TEST

static int aes128cloc(istream& in, istream& ad, ostream& out,
		const block_t& key, const char* nonce, bool hexout, const byte* mac) {
	ae_cxt cxt;
	ae_init(&cxt, (const byte*) key, sizeof(key));
	if(ad) {
		stringstream sstr;
		sstr << ad.rdbuf();
		const string& str = sstr.str();
		process_ad(&cxt, reinterpret_cast<const byte*>(str.c_str()), str.length(),
			reinterpret_cast<const byte*>(nonce), strlen(nonce));
	} else {
		process_ad(&cxt, reinterpret_cast<const byte*>(""), 0,
				reinterpret_cast<const byte*>(nonce), strlen(nonce));
	}
	stringstream sstr;
	sstr << in.rdbuf();
	const string& str = sstr.str();
	std::vector<byte> cif(16 * ((str.length() + 15)/16));
	std::vector<byte> tag(16);
	if( ! mac ) {
		ae_encrypt(&cxt, (byte*) str.c_str(), str.length(), cif.data(), tag.data(), tag.size(), ENC);
		out.write(reinterpret_cast<const char*>(cif.data()), str.length());
		if( hexout ) {
			hexwrapper{cout}.write(reinterpret_cast<const char*>(tag.data()),tag.size());
			cout << endl;
		} else {
			cout.write(reinterpret_cast<const char*>(tag.data()),tag.size());
		}
		return success;
	} else {
		auto len = str.length();
		if( mac == frominput ) {
			len -= 16;
			mac = reinterpret_cast<const byte*>(str.c_str() + len);
		}
		ae_encrypt(&cxt, cif.data(), len, (byte*) str.c_str(), tag.data(), tag.size(), DEC);
		out.write(reinterpret_cast<const char*>(cif.data()), cif.size());
		return (memcmp(tag.data(), mac, 16) == 0) ? success : err_verify;
	}
}

#else
static int aes128cloc(istream&, istream&, ostream&,
		const block_t&, const char*, bool, const byte* mac) throw(error) {
	throw error(string("aes128 is not available");
}
#endif

static int cloc(istream& in, istream& ad, ostream& out,
		const block_t& key, const char* nonce, bool hexout, bool tocerr) {
	crypto::chaskey::Cipher8::Cloc cloc(key);
	while(ad) {
		char plaintext[sizeof(block_t)];
		size_t len = ad.read(plaintext,sizeof(plaintext)).gcount();
		cloc.update((const uint8_t*)plaintext, len, ad.peek() == EOF);
	}
	if( nonce )
		cloc.nonce((const uint8_t*)nonce, strlen(nonce));
	while(in) {
		char plaintext[sizeof(block_t)];
		size_t len = in.read(plaintext,sizeof(plaintext)).gcount();
		cloc.encrypt(out, (const uint8_t*)plaintext, len, in.peek() == EOF);
	}
	if( tocerr ) {
		cloc.write(hexwrapper{cerr});
		cerr << endl;
	} else if( hexout ) {
		cloc.write(hexwrapper{cout});
		cout << endl;
	} else
		cloc.write(cout);
	return success;
}

static int uncloc(istream& in, istream& ad, ostream& out, const block_t& key,
		const char* nonce, const uint8_t* signature, uint_fast8_t len) {
	crypto::chaskey::Cipher8::Cloc cloc(key);
	while(ad) {
		char plaintext[sizeof(block_t)];
		size_t len = ad.read(plaintext,sizeof(plaintext)).gcount();
		cloc.update((const uint8_t*)plaintext, len, ad.peek() == EOF);
	}
	if( nonce )
		cloc.nonce((const uint8_t*)nonce, strlen(nonce));
	istream::pos_type end = (1ULL << 63) -1;
	if( signature == frominput ) {
		in.seekg(0, in.end);
		end = in.tellg();
		end -= sizeof(frominput);
		in.seekg(end, in.beg);
		in.read((char*)frominput,sizeof(frominput));
		in.seekg(0, in.beg);
		len = sizeof(frominput);
	}
	while(in && in.tellg() < end ) {
		char ciphertext[sizeof(block_t)];
		size_t pos = in.tellg();
		size_t size = ((pos + sizeof(block_t)) > end)
			? end - in.tellg()
			: sizeof(block_t);
		size_t len = in.read(ciphertext,size).gcount();
		cloc.decrypt(out, (const uint8_t*)ciphertext, len, in.peek() == EOF || size < sizeof(block_t));
	}
	if( signature && len )	return cloc.verify(signature, len) ? success : err_verify;
	cloc.write(hexwrapper{cerr});
	cerr << endl;
	return err_verify;
}


static int help() {
	cerr << "Usage: chaskey <operation> [options]" << endl
		 << "  <operation> is one of the following:" << endl
		 << "  -s     : sign message" << endl
		 << "  -m <x> : verify message signature <x>" << endl
		 << "  -e     : encrypt message" << endl
		 << "  -d     : decrypt message" << endl
		 << "  -c     : encrypt and sign message with CLOC" << endl
		 << "  -u <x> : decrypt with CLOC and verify message signature <x>" << endl
		 << "  -u .   : decrypt with CLOC and verify message signature against last block in input" << endl
		 << "  -u -   : decrypt with CLOC" << endl
		 << "  -t     : self-test" << endl
		 << "  [options] are :" << endl
		 << "  -I <m> : use message <m>" << endl
		 << "  -i <f> : read message from file <f>" << endl
		 << "  -o <f> : write output to file <f>" << endl
		 << "  -K <k> : set the key as byte string <k>" << endl
		 << "  -X <x> : set the key given as hexadecimal string <x>" << endl
		 << "  -N <n> : set the nonce as byte string <n>" << endl
		 << "  -V <x> : set the initialization vector as hexadecimal string <x>" << endl
		 << "  -A <n> : set the associated data as byte string <n>" << endl
		 << "  -a <f> : read associated data from file <f>" << endl
		 << "  -k <f> : read key from file <f>" << endl
		 << "  -h     : write signature in hexadecimal" << endl
		 << "  -2     : write hexadecimal signature to stderr" << endl
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


static void make_cbcmaster(int param) {
	crypto::chaskey::Chaskey8::Cbc cbc(get_test_vector(param));
	cbc.init(iv);
	cbc.encrypt(cout, get_test_message(), param, true);
}


static void make_clocmaster(int i) {
	const uint8_t* msg = get_test_message();
	crypto::chaskey::Chaskey8::Cloc cloc(get_test_vector(i));
	cloc.update(msg + i%5, i, i >= 8);
	if( i < 8 )
		cloc.update(msg + i%5, 16 - i, true);
	cloc.nonce(msg+i, i+3);
	cloc.encrypt(cout, msg, i+8, i >= 8);
	if( i < 8 )
		cloc.encrypt(cout, msg+(i+8), i, true);
	cloc.write(cout);
}

static bool make_masters(int param) {
	if( param >= 80 ) return false;
	if( param >= 64 ) make_clocmaster(param-64);
	else make_cbcmaster(param);
	return true;
}

int main(int argc, char * const argv[]) {
	options opts = {};
	block_t key, iv {};
	opts.hexout = isatty(fileno(stdout));
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
	ostream& out = output(opts);
	if( ! in || ! out ) return ioerror;
	switch(opts.oper) {
	case operation::sign:
		return sign(in, key, opts.hexout, opts.tocerr);
	case operation::verify: {
		uint8_t digest[16] {};
		auto len =  hex2bytes(opts.digest, digest, sizeof(digest));
		int res = verify(in, key, digest, len);
		if( verbosity > 1 && res == success )
			cerr << "Verified" << endl;
		if( verbosity >= 1 && res != success )
			cerr << "Not verified" << endl;
		return res;
		}
	case operation::encrypt:
		return encrypt(in, out, key, opts.nonce, iv);
	case operation::decrypt:
		return decrypt(in, out, key, opts.nonce, iv);
	case operation::cloc: {
		istream& ad ( adata(opts) );
		return opts.aes128cloc
			? aes128cloc(in, ad, out, key, opts.nonce, opts.hexout, nullptr)
		    : cloc(in, ad, out, key, opts.nonce, opts.hexout, opts.tocerr);
	}
	case operation::uncloc: {
		istream& ad ( adata(opts) );
		uint8_t digest[16] {};
		uint8_t * mac = digest;
		uint_fast8_t len = 0;
		if( opts.digest ) {
			if( strcmp(opts.digest, ".") == 0 ) {
				mac = frominput;
			} else
			if( strcmp(opts.digest, "-") == 0 ) {
				mac = nullptr;
			} else
				len = hex2bytes(opts.digest, digest, sizeof(digest));

		}
		if( ! ad ) return ioerror;
		int res = opts.aes128cloc
			? aes128cloc(in, ad, out, key, opts.nonce, len, digest)
			: uncloc(in, ad, out, key, opts.nonce, mac, len);
		if( verbosity > 1 && res == success )
			cerr << "Verified" << endl;
		if( verbosity >= 1 && res != success )
			cerr << "Not verified" << endl;
		return res;
	}
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
	case level::debug:
		break;
	default:
		return;
	}
	va_list args;
	va_start(args, fmt);
	vfprintf(file, fmt, args);
	va_end(args);
}
/* this substitues AES_encrypt to experiment with a reference
 * aes128cloc implementation
 * /
extern "C" void AES_encrypt(const unsigned char *in, unsigned char *out,
		 const AES_KEY *key) {
	using block_t = crypto::chaskey::Cipher<8>::block_t;
	crypto::chaskey::Cipher<8> & cipher = crypto::chaskey::Cipher8::cast(out);
	if( in != out )
		cipher ^=  *(const block_t*) in;
	cipher.permute();
	cipher ^= *(const block_t*) key->rd_key;

}
 //*/

