/*  Copyright (C) 2017 Eugene Hutorny <eugene@hutorny.in.ua>
 *
 *  test.cpp - self-testing facilities for a Chaskey Block Cipher algorithm
 *
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

#include "configuration.h"
#include <initializer_list>
#include <string.h>
#include "chaskey.h"
#include "chaskey.hpp"
#include "miculog.hpp"

struct memcpywrapper {
	uint8_t * data;
	size_t size;
	inline void write(const void* src, unsigned len) noexcept {
		memcpy(data, src, len);
		size += len;
		data += len;
	}
};

namespace crypto {
namespace test_compile {
	typedef uint32_t block_t[8];
	struct Algorithm {
		static void permute(block_t&) {}
		static void etumrep(block_t&) {}
	};
	Cbc<BlockCipherPrototype<block_t,Algorithm>,details::simple_formatter<uint32_t,8>> TestCbc;
	Mac<BlockCipherPrototype<block_t,Algorithm>,details::simple_formatter<uint32_t,8>> TestMac;

	void test() {
		uint8_t data[32];
		TestCbc.init(data, sizeof(data));
		TestCbc.encrypt(memcpywrapper{data}, data, sizeof(data), true);
		TestCbc.decrypt(memcpywrapper{data}, data, sizeof(data));
		TestMac.update(data, sizeof(data), true);
		TestMac.write(memcpywrapper{data});
		TestMac.verify(data);
	}
}
};


//#ifdef CHASKEY_HEAD2HEAD_TEST
extern void (*chaskey_cpp)(uint8_t *, uint32_t, const uint8_t *, const uint32_t,
		const uint32_t [4], const uint32_t [4], const uint32_t [4]);
extern void (*subkeys_cpp)(uint32_t [4], uint32_t [4], const uint32_t [4]);
//#endif

using namespace crypto;
using namespace chaskey;

struct Test {
	static const uint8_t * const masters[63];
	static const block_t vectors[64];
	static const char plaintext[];
};


struct vector : chaskey::Cipher<8> {
	inline vector(const item_t* val) noexcept {
		memcpy(v,val,sizeof(v));
	}
	using chaskey::Cipher<8>::dnour;
	using chaskey::Cipher<8>::round;
	inline void oround() noexcept {
#define ROTL(x,b) (uint32_t)( ((x) >> (32 - (b))) | ( (x) << (b)) )
	    v[0] += v[1]; v[1]=ROTL(v[1], 5); v[1] ^= v[0]; v[0]=ROTL(v[0],16);
	    v[2] += v[3]; v[3]=ROTL(v[3], 8); v[3] ^= v[2];
	    v[0] += v[3]; v[3]=ROTL(v[3],13); v[3] ^= v[0];
	    v[2] += v[1]; v[1]=ROTL(v[1], 7); v[1] ^= v[2]; v[2]=ROTL(v[2],16);
	}
};

using miculog::level;


struct Log : miculog::Log<TestLog>  {
	static inline constexpr const char* fmt() noexcept {
		return sizeof(int) == sizeof(short) ?
			"%s{%08lX,%08lX,%08lX,%08lX}\n":"%s{%08X,%08X,%08X,%08X}\n";
	}
	static const void block(level lvl, const char* msg, const block_t& b) noexcept {
		if( enabled(lvl) )
			appender::log(lvl, fmt(), msg, b[0],b[1],b[2],b[3]);
	}
	static const void block(level lvl, const char* msg, const void* p) noexcept {
		const block_t& b = *static_cast<const block_t*>(p);
		if( enabled(lvl) )
			appender::log(lvl, fmt(), msg, b[0],b[1],b[2],b[3]);
	}
} log;

using details::rol;
using details::ror;

bool test_vectors() {
  uint8_t m[64];
  uint8_t tag[16];
  uint32_t k[4] = { 0x833D3433, 0x009F389F, 0x2398E64F, 0x417ACF39 };
  uint32_t k1[4], k2[4];
  int i;
  int ok = 1;
  uint32_t taglen = 16;

  /* key schedule */
  subkeys(k1,k2,k);
  /* mac */
  for (i = 0; i < 64; i++) {
    m[i] = i;

    chaskey_cpp(tag, taglen, m, i, k, k1, k2);
    details::simple_formatter<uint32_t,4> buff;
    const block_t& result = buff.result(Test::vectors[i]);

    if (memcmp( tag, result, taglen )) {
      log.fail("test_vectors           : length %d\n",i);
      log.block(level::error, "got                    : ", tag);
      log.block(level::error, "expected               : ", result);
      ok = 0;
    }
  }

  return ok;
}

extern unsigned long milliseconds();

alignas(4)
static uint8_t blank[32];

unsigned long bench_refmac(unsigned long count) {
	block_t subkey1{}, subkey2{}, k1{};
	auto start = milliseconds();
	while(count--)
		::chaskey(blank, 16, blank, sizeof(blank), k1, subkey1, subkey2);
	return milliseconds() - start;
}

unsigned long bench_cppmac(unsigned long count) {
	block_t subkey1{}, subkey2{}, k1{};
	auto start = milliseconds();
	while(count--)
		chaskey_cpp(blank, 16, blank, sizeof(blank), k1, subkey1, subkey2);
	return milliseconds() - start;
}


struct blockassignwrapper {
	crypto::chaskey::Cipher8::Block& data;
	inline void write(const void* src, unsigned) noexcept {
		data = *reinterpret_cast<const block_t*>(src);
	}
};
unsigned long bench_mac(unsigned long count) {
	crypto::chaskey::Cipher8::Mac mac;
	block_t key{};
	crypto::chaskey::Cipher8::Block result;
	mac.set(key);
	auto start = milliseconds();
	while(count--) {
		mac.init();
		mac.update(blank,sizeof(blank),true);
		mac.write(blockassignwrapper{result});
	}
	return milliseconds() - start;
}

static crypto::chaskey::Cipher8::Block result[2];

unsigned long bench_encrypt(unsigned long count) {
	block_t key{}, iv{};
	crypto::chaskey::Cipher8::Cbc cbc;
	cbc.set(key);
	auto start = milliseconds();
	while(count--) {
		cbc.init(iv);
		cbc.encrypt(blockassignwrapper{result[0]},blank,sizeof(blank),true);
	}
	return milliseconds() - start;
}

unsigned long bench_decrypt(unsigned long count) {
	block_t key{}, iv{};
	crypto::chaskey::Cipher8::Cbc cbc;
	cbc.set(key);
	auto start = milliseconds();
	while(count--) {
		cbc.init(iv);
		cbc.decrypt(blockassignwrapper{result[0]},blank,sizeof(blank));
	}
	return milliseconds() - start;
}


bool bench(unsigned long count) {
	log.info("|%-12s|%-12s|%-12s|%-12s|%-12s|\n",
			"  Ref MAC", "  Cpp MAC", "   MAC"," Encrypt", " Decrypt");
	if( chaskey_cpp == &::chaskey )
		log.warn("|%-12s", " -- N/A --");
	else
		log.warn("|%8lu%4s", bench_refmac(count),"");
	log.warn("|%8lu%4s", bench_cppmac(count),"");
	log.warn("|%8lu%4s", bench_mac(count),"");
	log.warn("|%8lu%4s", bench_encrypt(count),"");
	log.warn("|%8lu%4s|", bench_decrypt(count),"");
	log.warn("\n");
	return true;
}

/**
 * test rotation functions
 */
unsigned test_rolror(const block_t& v) {
	unsigned res = 0;
	for(auto i : {16,17,13,8,5}  ) {
		if( (ror(v[0],i) == rol(v[0],i)) != (i==16) ) {
			log.fail( "test_rolror/ror!=rol             : %d\n",i);
		    log.error("ror(%08X,%d)                 :", ror(v[0],i));
		    log.error("rol(%08X,%d)                 :", rol(v[0],i));
			++res;
		}
		if( rol(ror(v[0],i),i) != v[0] ) {
			log.fail( "test_rolror/rol(ror)             : %d\n",i);
			log.error("rol(ror(%08X,%d),%d)         : %08X\n",v[0],i,i,rol(ror(v[0],i),i));
			++res;
		}
	}
	return res;
}

/**
 * test transformation
 */
unsigned test_transform(const block_t& v) {
	unsigned res = 0;
	vector o(v), r(v), m(v);
	o.oround();
	r.round();
	if( r != o ) {
		log.block(level::fail, "test_transform/round             :", v);
		log.block(level::error,"expected                         :", o);
		log.block(level::error,"got                              :", r);
		++res;
	}
	r.dnour();
	if( r != m ) {
		log.block(level::fail, "test_transform/dnour             :", v);
		log.block(level::error,"expected                         :", m);
		log.block(level::error,"got                              :", r);
		++res;
	}
	r.permute();
	r.etumrep();
	if( r != m ) {
		log.block(level::fail, "test_transform/etumrep           :", v);
		log.block(level::error,"expected                         :", m);
		log.block(level::error,"got                              :", r);
		++res;
	}
	return res;
}

/**
 * test MAC reference chaskey head-to-head with crypto::chaskey implementations
 */
unsigned test_head2head(const block_t& v) {
	unsigned res = 0;
#	ifdef CHASKEY_HEAD2HEAD_TEST
	block_t subkey1, subkey2, k1, k2;
	subkeys(subkey1, subkey2, v);
	subkeys_cpp(k1,k2, v);
	if( memcmp(k1, subkey1, sizeof(k1)) != 0 ) {
		log.block(level::fail, "test_head2head/subkey1 :", subkey1);
		++res;
	}
	if( memcmp(k2, subkey2, sizeof(k2)) != 0 ) {
		log.block(level::fail, "test_head2head/subkey2 :", subkey2);
		++res;
	}
	block_t tag = {};
	block_t mtag;
	for(auto i: {15, 16, 17, 31, 32, 33, 47, 48, 49, 50}) {
		::chaskey((uint8_t*)tag, sizeof(tag), (uint8_t*)Test::plaintext+(i&3), i, v, subkey1, subkey2);
		chaskey_cpp((uint8_t*)mtag, sizeof(mtag), (uint8_t*)Test::plaintext+(i&3), i, v, subkey1, subkey2);
		if( memcmp(tag,mtag, sizeof(mtag)) != 0 ) {
			log.block(level::fail, "test_head2head/mismatch          :", tag);
			log.block(level::error,"expected                         :", mtag);
			log.error("message                          :'%.*s'\n", i, Test::plaintext+(i&3));
			++res;
		}
	}
#	endif
	return res;
}

/**
 * test MAC primitive with whole and partial messages
 */
unsigned test_mac(const block_t& v) {
	unsigned res = 0;
	block_t tag = {};
	crypto::chaskey::Cipher8::Mac mac;
	block_t subkey1, subkey2;
	subkeys(subkey1, subkey2, v);

	mac.set(v);
	for(auto i: {15, 16, 17, 31, 32, 33, 47, 48, 49, 50}) {
		uint8_t* msg = (uint8_t*)(Test::plaintext+(i&3));
		chaskey_cpp((uint8_t*)&tag, sizeof(tag), msg, i, v, subkey1, subkey2);
		mac.init();
		mac.update(msg, i, true);
		if( ! mac.verify(tag) ) {
			block_t got = {};
			mac.write(memcpywrapper{(uint8_t*)&got, sizeof(got)});
			log.block(level::fail, "test_mac/verify        :", got);
			log.block(level::error,"expected               :", tag);
			log.error("message                :'%.*s' %d bytes\n", i, msg, i);
			++res;
		}
	}
	unsigned len = 0;
	uint8_t* msg = (uint8_t*)(Test::plaintext);
	mac.init();
	for(auto i: {15, 17, 1, 14, 13}) {
		mac.update(msg, i, i == 13);
		msg += i;
		len += i;
	}
	chaskey_cpp((uint8_t*)&tag, sizeof(tag), (uint8_t*)(Test::plaintext), len, v, subkey1, subkey2);
	if( ! mac.verify(tag) ) {
		block_t got = {};
		mac.write(memcpywrapper{(uint8_t*)&got, sizeof(got)});
		log.block(level::fail, "test_mac/update        :", got);
		log.block(level::error,"expected               :", tag);
		log.error("message                :'%.*s'\n", len, Test::plaintext);
		res = false;
	}
	return res;
}

const block_t iv { };
/**
 * test CBC primitive encrypt/decrypt
 */
unsigned test_cbc(const block_t& v) {
	unsigned res = 0;
	crypto::chaskey::Cipher8::Cbc cbc;
	uint8_t tmp[64];
	uint8_t plain[64];
	cbc.set(v);
	for(auto i: {7, 8, 9, 15, 16, 17, 31, 32, 33, 47, 48, 49, 50}) {
		cbc.init(iv);
		memcpywrapper wrp{tmp};
		cbc.encrypt(wrp, (const uint8_t*)Test::plaintext, i, true);
		cbc.init(iv);
		cbc.decrypt(memcpywrapper{plain}, tmp, wrp.size);
		if( strncmp(Test::plaintext,(const char*)plain, i) != 0) {
			log.fail( "test_cbc               :\t'%.*s'\n", i, Test::plaintext);
			log.error("got                    :\t'%.*s'\n", i, plain);
			++res;
		}
	}
	return res;
}

/**
 * test CBC adinst masters
 */
unsigned test_master() {
	unsigned res = 0;
	uint8_t tmp[64];
	for(int i = 1; i < 64; ++i) {
		crypto::chaskey::Cipher8::Cbc cbc;
		cbc.set(Test::vectors[i]);
		cbc.init(iv);
		memcpywrapper out{tmp};
		cbc.encrypt(out, (const uint8_t*)Test::plaintext, i, true);
		if( memcmp(tmp,Test::masters[i-1],out.size) != 0 ) {
			log.fail("test_master/encrypt    :'%.*s'\n", i, Test::plaintext);
			++res;
		}
		cbc.init(iv);
		cbc.decrypt(memcpywrapper{tmp}, Test::masters[i-1], out.size);
		if( memcmp(tmp,Test::plaintext,i) != 0 ) {
			log.fail("test_master/decrypt    :'%.*s'\n", i, Test::plaintext);
			++res;
		}
	}
	return res;
}

const block_t& get_test_vector(unsigned i) {
	if(i > 63) i = 0;
	return Test::vectors[i];
}
const uint8_t* get_test_message() {
	return (const uint8_t*) Test::plaintext;
}

bool test_debug() {
	return true;
}

bool test() {
	if( ! test_debug() ) return false;
	log.info("Running self-test %s\n", (chaskey_cpp == &::chaskey ?
			"without head-2-head" : "with head-2-head"));
	unsigned res = ! test_vectors();
	for(const block_t& v : Test::vectors) {
		log.info(".");
		res += test_rolror(v);
		res += test_transform(v);
		res += test_cbc(v);
	}
	log.info(".");
	if( chaskey_cpp != &::chaskey )
		res += test_head2head(Test::vectors[0]);
	log.info(".");
	res += test_mac(Test::vectors[0]);
	log.info(".");
	res += test_master();
	if( res )
		log.warn("\n%d tests failed\n", res);
	else
		log.warn("\nAll tests pass\n");
	return ! res;
}

const char Test::plaintext[] = "Plain text message of sufficient length. "
		"Plain text message of sufficient length";


const block_t Test::vectors[64] =
{
  { 0x792E8FE5, 0x75CE87AA, 0x2D1450B5, 0x1191970B },
  { 0x13A9307B, 0x50E62C89, 0x4577BD88, 0xC0BBDC18 },
  { 0x55DF8922, 0x2C7FF577, 0x73809EF4, 0x4E5084C0 },
  { 0x1BDBB264, 0xA07680D8, 0x8E5B2AB8, 0x20660413 },
  { 0x30B2D171, 0xE38532FB, 0x16707C16, 0x73ED45F0 },
  { 0xBC983D0C, 0x31B14064, 0x234CD7A2, 0x0C92BBF9 },
  { 0x0DD0688A, 0xE131756C, 0x94C5E6DE, 0x84942131 },
  { 0x7F670454, 0xF25B03E0, 0x19D68362, 0x9F4D24D8 },
  { 0x09330F69, 0x62B5DCE0, 0xA4FBA462, 0xF20D3C12 },
  { 0x89B3B1BE, 0x95B97392, 0xF8444ABF, 0x755DADFE },
  { 0xAC5B9DAE, 0x6CF8C0AC, 0x56E7B945, 0xD7ECF8F0 },
  { 0xD5B0DBEC, 0xC1692530, 0xD13B368A, 0xC0AE6A59 },
  { 0xFC2C3391, 0x285C8CD5, 0x456508EE, 0xC789E206 },
  { 0x29496F33, 0xAC62D558, 0xE0BAD605, 0xC5A538C6 },
  { 0xBF668497, 0x275217A1, 0x40C17AD4, 0x2ED877C0 },
  { 0x51B94DA4, 0xEFCC4DE8, 0x192412EA, 0xBBC170DD },
  { 0x79271CA9, 0xD66A1C71, 0x81CA474E, 0x49831CAD },
  { 0x048DA968, 0x4E25D096, 0x2D6CF897, 0xBC3959CA },
  { 0x0C45D380, 0x2FD09996, 0x31F42F3B, 0x8F7FD0BF },
  { 0xD8153472, 0x10C37B1E, 0xEEBDD61D, 0x7E3DB1EE },
  { 0xFA4CA543, 0x0D75D71E, 0xAF61E0CC, 0x0D650C45 },
  { 0x808B1BCA, 0x7E034DE0, 0x6C8B597F, 0x3FACA725 },
  { 0xC7AFA441, 0x95A4EFED, 0xC9A9664E, 0xA2309431 },
  { 0x36200641, 0x2F8C1F4A, 0x27F6A5DE, 0x469D29F9 },
  { 0x37BA1E35, 0x43451A62, 0xE6865591, 0x19AF78EE },
  { 0x86B4F697, 0x93A4F64F, 0xCBCBD086, 0xB476BB28 },
  { 0xBE7D2AFA, 0xAC513DE7, 0xFC599337, 0x5EA03E3A },
  { 0xC56D7F54, 0x3E286A58, 0x79675A22, 0x099C7599 },
  { 0x3D0F08ED, 0xF32E3FDE, 0xBB8A1A8C, 0xC3A3FEC4 },
  { 0x2EC171F8, 0x33698309, 0x78EFD172, 0xD764B98C },
  { 0x5CECEEAC, 0xA174084C, 0x95C3A400, 0x98BEE220 },
  { 0xBBDD0C2D, 0xFAB6FCD9, 0xDCCC080E, 0x9F04B41F },
  { 0x60B3F7AF, 0x37EEE7C8, 0x836CFD98, 0x782CA060 },
  { 0xDF44EA33, 0xB0B2C398, 0x0583CE6F, 0x846D823E },
  { 0xC7E31175, 0x6DB4E34D, 0xDAD60CA1, 0xE95ABA60 },
  { 0xE0DC6938, 0x84A0A7E3, 0xB7F695B5, 0xB46A010B },
  { 0x1CEB6C66, 0x3535F274, 0x839DBC27, 0x80B4599C },
  { 0xBBA106F4, 0xD49B697C, 0xB454B5D9, 0x2B69E58B },
  { 0x5AD58A39, 0xDFD52844, 0x34973366, 0x8F467DDC },
  { 0x67A67B1F, 0x3575ECB3, 0x1C71B19D, 0xA885C92B },
  { 0xD5ABCC27, 0x9114EFF5, 0xA094340E, 0xA457374B },
  { 0xB559DF49, 0xDEC9B2CF, 0x0F97FE2B, 0x5FA054D7 },
  { 0x2ACA7229, 0x99FF1B77, 0x156D66E0, 0xF7A55486 },
  { 0x565996FD, 0x8F988CEF, 0x27DC2CE2, 0x2F8AE186 },
  { 0xBE473747, 0x2590827B, 0xDC852399, 0x2DE46519 },
  { 0xF860AB7D, 0x00F48C88, 0x0ABFBB33, 0x91EA1838 },
  { 0xDE15C7E1, 0x1D90EFF8, 0xABC70129, 0xD9B2F0B4 },
  { 0xB3F0A2C3, 0x775539A7, 0x6CAA3BC1, 0xD5A6FC7E },
  { 0x127C6E21, 0x6C07A459, 0xAD851388, 0x22E8BF5B },
  { 0x08F3F132, 0x57B587E3, 0x087AD505, 0xFA070C27 },
  { 0xA826E824, 0x3F851E6A, 0x9D1F2276, 0x7962AD37 },
  { 0x14A6A13A, 0x469962FD, 0x914DB278, 0x3A9E8EC2 },
  { 0xFE20DDF7, 0x06505229, 0xF9C9F394, 0x4361A98D },
  { 0x1DE7A33C, 0x37F81C96, 0xD9B967BE, 0xC00FA4FA },
  { 0x5FD01E9A, 0x9F2E486D, 0x93205409, 0x814D7CC2 },
  { 0xE17F5CA5, 0x37D4BDD0, 0x1F408335, 0x43B6B603 },
  { 0x817CEEAE, 0x796C9EC0, 0x1BB3DED7, 0xBAC7263B },
  { 0xB7827E63, 0x0988FEA0, 0x3800BD91, 0xCF876B00 },
  { 0xF0248D4B, 0xACA7BDC8, 0x739E30F3, 0xE0C469C2 },
  { 0x67363EB6, 0xFAE8E047, 0xF0C1C8E5, 0x828CCD47 },
  { 0x3DBD1D15, 0x05092D7B, 0x216FC6E3, 0x446860FB },
  { 0xEBF39102, 0x8F4C1708, 0x519D2F36, 0xC67C5437 },
  { 0x89A0D454, 0x9201A282, 0xEA1B1E50, 0x1771BEDC },
  { 0x9047FAD7, 0x88136D8C, 0xA488286B, 0x7FE9352C }
};

/* echo '' > tests/master.inc; for i in `seq 1 63`; do
 * echo const uint8_t master$i[] = { `Debug/chaskey -T $i | file2c` }\; >> tests/master.inc; done;
 */
#include "master.inc"

const uint8_t * const Test::masters[] = {
	master1, master2, master3, master4, master5, master6, master7, master8,
	master9 ,master10,master11,master12,master13,master14,master15,master16,
	master17,master18,master19,master20,master21,master22,master23,master24,
	master25,master26,master27,master28,master29,master30,master31,master32,
	master33,master34,master35,master36,master37,master38,master39,master40,
	master41,master42,master43,master44,master45,master46,master47,master48,
	master49,master50,master51,master52,master53,master54,master55,master56,
	master57,master58,master59,master60,master61,master62,master63
};
