/* chaskey.hpp - a C++ implementation of Chaskey algorithm in MAC and CBC modes
 * Chaskey algorithm invented by Nicky Mouha http://mouha.be/chaskey/
 *
 * Copyright (C) 2017 Eugene Hutorny <eugene@hutorny.in.ua>
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

#pragma once
#include <stdint.h>
#include <byteswap.h>

namespace crypto {

/*
 * Ready to use crypto primitives are at the bottom of this header:
 * crypto::chaskye::Cipher8::Mac
 * crypto::chaskye::Cipher8::Cbc
 * crypto::chaskye::Chaskye8
 */

/**
 * BlockCipherPrototype - a template-skeleton for implementing block ciphers
 * BlockType is an array of integers
 * Algorithm must implement
 * 1.  void permute(Block&);			- forward transform
 * 2.  void etumrep(Block&);			- reverse transform
 */

template<typename BlockType, class Algorithm>
class BlockCipherPrototype {
public:
	using block_t = BlockType;
	using Block =  BlockCipherPrototype;
	inline void permute() noexcept {
		Algorithm::permute(data);
	}
	inline void etumrep() noexcept {
		Algorithm::etumrep(data);
	}
	inline void operator^=(const block_t& val) noexcept {}
	inline void operator=(const block_t& val) noexcept {}
	const void* raw() const noexcept { return data; }
	operator const block_t&() const noexcept { return data; }
	operator block_t&() noexcept { return data; }
	static constexpr uint_fast8_t size() noexcept { return sizeof(data); }
	inline void init(const block_t& block) noexcept { operator=(block);	}
	static inline void derive(block_t&, const block_t&) noexcept {}
	static inline constexpr
	BlockCipherPrototype& cast(Block& block) noexcept {
		return static_cast<BlockCipherPrototype&>(block);
	}
	static inline constexpr
	const BlockCipherPrototype& cast(const void* block) noexcept {
		return *reinterpret_cast<const BlockCipherPrototype*>(block);
	}
private:
	BlockType data;
};

/**
 * BlockCipher in the Cipher Block Chaining Mode (CBC)
 * In this mode BlockCipher is used to encrypt and decrypt messages
 * http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
 * chapter 6.2
 */
template<class Cipher, class Formatter>
class Cbc : protected Cipher {
public:
	using typename Cipher::block_t;
	using typename Cipher::Block;
	typedef typename Formatter::size_t size_t;
	inline Cbc() noexcept {}
	inline Cbc(const Cbc&) = delete; /* no copy constructor */
	explicit inline Cbc(const block_t&& _key) noexcept  { set(_key); }
	explicit inline Cbc(const block_t& _key) noexcept { set(_key); }

	/** set the secret key 													*/
	inline void set(const block_t& _key) noexcept {	key = _key;	}
	/** initialize the cipher with initialization vector iv					*/
	inline void init(const block_t& iv) noexcept {
		/* According to nistspecialpublication800-38a.pdf 6.2
		 * iv is xored with the first block of plain text and then passed to
		 * Cipher transformation. In this implementation state that is passed to
		 * next iteration is stored in Cipher and xored with plain text
		 * Thus, first block passed to transformation is: K ^ IV ^ M1
		 * Here we do            : K = K ^ IV
		 * and when encrypting M1: K = K ^ M1
		 * result is the same    : K =(K ^ IV) ^ M1
		 */
		Cipher::init(key);
		*this ^= iv;
	}
	/**
	 * Initializes vector by running forward cipher function on nonce
	 */
	inline void init(const void* nonce, size_t len) noexcept {
		/* NIST Special Publication 800-38a
		 * IV generation, recommended method number first.
		 * Apply the forward cipher function, under the same key that is
		 * used for the encryption of the plaintext, to a nonce
		 *
		 * http://web.cs.ucdavis.edu/~rogaway/papers/modes.pdf 1.9.3, page 8
		 * Appendix C of NIST SP 800-38A is wrong to recommend that, to create
		 * the IV for CBC or CFB modes, one can “apply the forward cipher
		 * function, under the same key that is used for encryption
		 * of the plaintext, to a nonce”	  								*/
		block_t subkey;
		Cipher::derive(subkey,key);
		Cipher::init(subkey);
		const uint8_t* msg = (const uint8_t*)nonce;
		do {
			encrypt(msg, len, true);
			buff.reset();
		} while( len );
	}
	/**
	 * Encrypts message msg of length len and writes it to the output stream
	 * if final == true, the message is padded o the size of block
	 */
	template<class stream>
	inline void encrypt(stream&& output, const uint8_t* msg, size_t len, bool final) noexcept {
		do {
			if( ! encrypt(msg, len, final) ) return;
			const block_t& result = buff.result(*this);
			/* cast to match std::ostrem::write signature,
			 * TODO cast to type of the first argument of write 			*/
			output.write(reinterpret_cast<const char*>(result), sizeof(block_t));
			buff.reset();
		} while( len );
	}
	/**
	 * Decrypts message msg of length len and writes it to the output stream
	 */
	template<class stream>
	inline void decrypt(stream&& output, const uint8_t* msg, size_t len) noexcept {
		do {
			buff.append(msg, len);
			if( ! buff.full() ) {
				return;
			}
			Block block;
			decrypt(buff.block(), block);
			const block_t& result = buff.result(block);
			/* cast to match std::ostrem::write signature,
			 * TODO cast to type of the first argument of write 			*/
			output.write(reinterpret_cast<const char*>(result), sizeof(block_t));
			buff.reset();
		} while( len );
	}
protected:
	inline bool encrypt(const uint8_t*& msg, size_t& len, bool final) noexcept {
		buff.append(msg, len);
		if( ! buff.full() )	{
			if( final ) buff.pad(0);
			else return false;
		}
		encrypt(buff.block());
		return true;
	}

	inline void encrypt(const block_t& input) noexcept {
		*this  ^= input;
		Cipher::permute();
		/* cipher stores only its state, so the key is applied here		*/
		*this  ^= key;
	}
	inline void decrypt(const block_t& input, Block& output) noexcept {
		output = input;
		output ^= key;
		Cipher::cast(output).etumrep();
		output ^= *this;
		static_cast<Block&>(*this) = input; /* Block is not directly visible */
	}

private:
	Block key;
	Formatter buff;
};

/**
 * BlockCipher in Authentication Mode
 * In this mode CBC is used to generate and verify message signature
 * http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38b.pdf
 * chapter 5.4
 * One primary key and two derived keys are used to strengthen against
 * known CBC-MAC attacks chapter 5.3
 */
template<class Cipher, class Formatter>
class Mac : protected Cipher {
public:
	using typename Cipher::Block;
	using typename Cipher::block_t;
	using size_t = uint_fast16_t;		/* not expecting chunks larger 64K  */
	inline Mac() noexcept {}
	inline Mac(const Mac&) = delete; 	/* no copy constructor 				*/
	explicit inline Mac(const block_t&& _key) noexcept  { set(_key); }
	explicit inline Mac(const block_t& _key) noexcept { set(_key); }

	/** sets the secret key to use 											*/
	inline void set(const block_t& _key) noexcept {
		key = _key;
		Cipher::derive(subkey1, key);
		Cipher::derive(subkey2, subkey1);
		init();
	}
	/** initializes cipher 													*/
	inline void init() noexcept { Cipher::init(key); }
	/** processes message chunk msg of length len,
	 *  final finishes generation by padding the message to the size of
	 *  block and applying one of derived keys  							*/
	inline void update(const uint8_t* msg, size_t len, bool final) noexcept {
		Block* finalkey = &subkey1;
		do {
			buff.append(msg, len);
			if( ! len ) {
				if( final ) {
					if( ! buff.full() ) {
						buff.pad(1);
						finalkey = &subkey2;
					}
					*this ^= *finalkey;
				} else {
					if( buff.available() != sizeof(block_t) ) return;
				}
			}
			encrypt(buff.block());
			buff.reset();
		} while( len );
		if( final ) {
			*this ^= *finalkey;
			buff.final(*this);
		}
	}
	template<class stream>
	void write(stream&& output) const noexcept {
		output.write(reinterpret_cast<const char*>(Cipher::raw()),Cipher::size());
	}
	bool verify(const void* tag) const noexcept {
		return Cipher::Block::cast(tag) == *this;
	}
protected:
	inline void encrypt(const block_t& input) noexcept {
		/* nistspecialpublication800-38b.pdf 6.2
		 * says M1 should be transformed without first xoring
		 * In Chaskey, there is a xoring of M1
		 */
		*this  ^= input;
		Cipher::permute();
	}
private:
	Block key;
	Block subkey1;
	Block subkey2;
	Formatter buff;
};

namespace details {

struct arch_traits {
	/* free standing constexpr not yet available,
	 * therefore it has to be placed inside  a struct 							*/
	static bool constexpr big_endian = __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__;
#	ifdef __xtensa__
	/* unaligned access to uint32_t causes system fault on esp8266			 */
	static bool constexpr direct_safe = false;
#	else
	static bool constexpr direct_safe = ! big_endian;
#endif
};

/**
 * Rotate right operation
 * gcc compiler generates
 * for i386: ror
 * for arm:  mov.w	r2, r2, ror
 * for mips: srl; slr; or
 *    (mips it does not seem to have ror)
 */
template<typename T>
inline constexpr T ror(T val, uint_fast8_t N) noexcept {
	return (val << (sizeof(T)*8 - N)) | ((val) >> (N));
}

/**
 * Rotate left operation
 */
template<typename T>
static inline T rol(T x, int b) {
	return (x >> (32 - b)) | ((x) << (b));
}

/**
 * Handles byte order
 */
template<bool=arch_traits::big_endian>
struct endian;

template<>
struct endian<false> {
	template<uint_fast8_t N>
	static inline constexpr uint_fast8_t index(uint_fast8_t val) noexcept {
		return val;
	}
	template<typename T>
	static inline constexpr T byteswap(T v) noexcept { return v; }
};

template<>
struct endian<true> {
	template<uint_fast8_t N>
	static inline constexpr uint_fast8_t index(uint_fast8_t val) noexcept {
		return (val|(N-1)) - (val&(N-1));
	}
	template<typename T>
	static inline T byteswap(uint32_t val) noexcept;
};

template<>
inline uint32_t endian<true>::byteswap(uint32_t val) noexcept {
	return bswap_32(val);
}

/**
 * Cross-platform byte-reordering block formatter
 */
template<typename T, unsigned N>
class simple_formatter {
public:
	typedef uint_fast16_t size_t; /* not expecting chunks larger 64K  */
	typedef T block_t[N];
	inline void append(const uint8_t*& msg, size_t& len) noexcept {
		while( pos < sizeof(data.b) && len ) {
			data.b[endian<>::index<sizeof(T)>(pos++)] = *msg++;
			--len;
		}
	}
	inline size_t append(const block_t& block) noexcept {
		const uint8_t* msg = reinterpret_cast<const uint8_t*>(block);
		size_t len = sizeof(block_t);
		append(msg, len);
		return sizeof(block_t) - len;
	}
	inline void pad(uint8_t chr) noexcept {
		while( pos < sizeof(data.b) ) {
			data.b[endian<>::index<sizeof(T)>(pos++)] = chr;
			chr = 0;
		}
	}
	inline uint_fast8_t available() const noexcept {
		return pos;
	}
	inline bool full() const noexcept {
		return available() == sizeof(data.b);
	}
	inline void reset() noexcept {
		pos = 0;
	}
	inline const block_t& block() const noexcept {
		return data.w;
	}
	/**
	 * reorder bytes in-place
	 */
	static inline void final(block_t& block) noexcept {
		if( arch_traits::big_endian ) {
			for(T& p : block) p = endian<>::byteswap<T>(p);
		}
	}
	/**
	 * reorder bytes in data
	 */
	inline const block_t& result(const block_t& block) noexcept {
		if( arch_traits::big_endian ) {
			for(uint_fast8_t i=0; i < N; ++i)
				data.w[i] = endian<>::byteswap<T>(block[i]);
			return data.w;
		}
		return block;
	}
private:
	/* union is used to get proper alignment on data						*/
	union {
		block_t w;
		uint8_t b[sizeof(w)];
	} data; /* alignas(T); // this does not work on some older compilers	*/
	uint_fast8_t pos = 0;
};

/**
 * block_formatter - implements transparent switch from data being accessed
 * directly via pointer or via an internal buffer.
 * Buffering is needed in the following cases:
 * 1. last block of shorter length stored and padded in the buffer
 * 2. on big-endian machines data must be reordered
 * 3. if an integer cannot be accessed via unaligned pointer
 */
template<typename T, unsigned N, bool direct = arch_traits::direct_safe>
class block_formatter;

template<typename T, unsigned N>
class block_formatter<T,N,false> : public simple_formatter<T,N> {};

template<typename T, unsigned N>
class block_formatter<T,N,true> : public simple_formatter<T,N> {
public:
	typedef simple_formatter<T,N> base;
	using typename base::block_t;
	using typename base::size_t;
	inline void append(const uint8_t*& msg, size_t& len) noexcept {
		if( len < sizeof(block_t) || base::available() ) {
			base::append(msg, len);
			raw = &base::block();
			size = 0;
		} else {
			raw = reinterpret_cast<const block_t*>(msg);
			msg += sizeof(block_t);
			len -= sizeof(block_t);
			size = sizeof(block_t);
		}
	}
	inline const block_t& block() const noexcept {
		return *raw;
	}
	inline void reset() noexcept {
		base::reset();
		raw = &base::block();
		size = 0;
	}
	inline uint_fast8_t available() const noexcept {
		return size + base::available();
	}
	inline bool full() const noexcept {
		return available() == sizeof(block_t);
	}
private:
	const block_t* raw = nullptr;
	uint_fast8_t size = 0;
};

/**
 * Block of bits stored as of N elements of type T
 */
template<typename T, uint_fast8_t N>
class block {
public:
	typedef decltype(N) index_t;
	typedef T item_t;
	typedef T block_t[N];
	typedef uint8_t raw_t[sizeof(block_t)];
	static constexpr unsigned count = N;	/* count of items */

	inline operator const block_t&() const noexcept {
		return v;
	}
	inline operator block_t&() noexcept {
		return v;
	}
	inline void operator=(const block_t& val) noexcept {
		assign(val);
	}
	inline void operator=(const block<T,N>& val) noexcept {
		assign(val.v);
	}
	/* operator== and operator!= are used only in tests */
	inline bool operator==(const block& val) const noexcept {
		bool res = true;
		for(auto i = N; i--; ) res &= v[i] == val.v[i];
		return res;
	}
	inline bool operator!=(const block& val) const noexcept {
		bool res = false;
		for(auto i = N; i--; ) res |= v[i] != val.v[i];
		return res;
	}
	
	inline void operator^=(const block_t& val) noexcept {
		operator^=(reinterpret_cast<const block<T,N>&>(val));
	}
	inline void operator^=(const block<T,N>& val) noexcept {
		/* compiler effectively unrolls this loop if optimizes for speed */
		for(auto i = N; i--; ) v[i] ^= val.v[i];
	}
	static constexpr const block& cast(const void* blk) noexcept {
		static_assert(static_cast<const block*>(nullptr)->v==nullptr,
				"Block bias detected");
		return *reinterpret_cast<const block*>(blk);
	}
	static constexpr block& cast(void* blk) noexcept {
		static_assert(static_cast<const block*>(nullptr)->v==nullptr,
				"Block bias detected");
		return *reinterpret_cast<block*>(blk);
	}
	const raw_t& raw() const noexcept {
		return reinterpret_cast<const raw_t&>(v);
	}
	raw_t& raw() noexcept {
		return reinterpret_cast<raw_t&>(v);
	}
	static constexpr uint_fast8_t size() noexcept {
		return sizeof(v);
	}
protected:
	T v[N];
	inline void assign(const block_t& val) noexcept {
		/* this implementation uses array-by-element assignment
		 * if memcpy is more desirable,  derive this class
		 * hide method assign and operator= with alternatives
		 * calling memcpy, and than use the derived class in
		 * crypto templates 											*/
		for(auto i = N; i--; ) v[i] = val[i];
	}
};
}

namespace chaskey {

/**
 * Cipher - block of 128 bits with N-round permutation
 */
template<unsigned N>
class Cipher : public details::block<uint32_t, 4> {
public:
	typedef details::block<uint32_t, 4> base;
	using base::block_t;
	using Block = details::block<uint32_t, 4>;
	using Cbc = crypto::Cbc<Cipher,details::block_formatter<item_t,count>>;
	using Mac = crypto::Mac<Cipher,details::block_formatter<item_t,count>>;
	/**
	 * Chaskey transformation
	 */
	inline void permute() noexcept {
		/* compiler effectively unrolls this loop if optimizes for speed */
		for(auto i=N; i--;) round();
	}
	/**
	 * Chaskey reverse transformation
	 */
	inline void etumrep() noexcept {
		/* compiler effectively unrolls this loop if optimizes for speed */
		for(auto i=N; i--;) dnour();
	}
	/** shifts entire block one bit left and distorts lowest byte  */
	static inline void derive(block_t& v, const block_t& in) noexcept {
		/* operations reordered to make it callable on self */
		item_t C =  static_cast<int32_t>(in[3]) >> (32-1); /* replicate sign bit */
		v[3] = (in[3] << 1) | (in[2] >> (32-1));
	    v[2] = (in[2] << 1) | (in[1] >> (32-1));
	    v[1] = (in[1] << 1) | (in[0] >> (32-1));
	    v[0] = (in[0] << 1) ^ (C & 0x87);
	}
	static constexpr const Cipher& cast(const void* blk) noexcept {
		return static_cast<const Cipher&>(base::cast(blk));
	}
	static constexpr Cipher& cast(void* blk) noexcept {
		return static_cast<Cipher&>(base::cast(blk));
	}
protected:
	/**
	 * Chaskey round
	 */
	inline void round() noexcept {
		using namespace details;
		v[0] += v[1];
		v[1]  = rol<item_t>(v[1], 5);
		v[1] ^= v[0];
		v[0]  = rol<item_t>(v[0],16);
		v[2] += v[3];
		v[3]  = rol<item_t>(v[3], 8);
		v[3] ^= v[2];
		v[0] += v[3];
		v[3]  = rol<item_t>(v[3],13);
		v[3] ^= v[0];
		v[2] += v[1];
		v[1]  = rol<item_t>(v[1], 7);
		v[1] ^= v[2];
		v[2]  = rol<item_t>(v[2],16);
	}
	/**
	 * Chaskey reverse round
	 */
	inline void dnour() noexcept {
		using namespace details;
		v[2]  = ror<item_t>(v[2],16);
		v[1] ^= v[2];
		v[1]  = ror<item_t>(v[1], 7);
		v[2] -= v[1];
		v[3] ^= v[0];
		v[3]  = ror<item_t>(v[3],13);
		v[0] -= v[3];
		v[3] ^= v[2];
		v[3]  = ror<item_t>(v[3], 8);
		v[2] -= v[3];
		v[0]  = ror<item_t>(v[0],16);
		v[1] ^= v[0];
		v[1]  = ror<item_t>(v[1], 5);
		v[0] -= v[1];
	}
	inline void init(const block_t& key) noexcept {
		assign(key);
	}
};

typedef details::block<uint32_t, 4>::block_t block_t;

/**
 * Cipher8 - implements Chaskey 8-round ciphering
 */
struct Cipher8 : chaskey::Cipher<8> {
	static unsigned constexpr count = chaskey::Cipher<8>::count; /* == 4 */
};

/**
 * Chaskey8 - implements reference Chaskey message authentication algorithm
 * 			  with the key and two its subkeys provided by the caller
 */
class Chaskey8 : public Cipher8 {
public:
	typedef uint8_t tag_t[sizeof(block_t)];
	/**
	 * computes message digest, and writes results to tag
	 */
	void sign(tag_t& tag, const uint8_t* msg, uint_fast16_t len,
			const block_t& key,	const block_t& subkey1,
			const block_t& subkey2) noexcept {
		details::block_formatter<item_t, count> buff;
		const block_t* finalkey = nullptr;
		init(key);
		do {
			buff.append(msg, len);
			if( ! len ) {
				if( buff.available() == sizeof(block_t) )
					finalkey = &subkey1;
				else {
					buff.pad(1);
					finalkey = &subkey2;
				}
				*this ^= *finalkey;
			}
			*this ^= buff.block();
			permute();
			buff.reset();
		} while( len );
		*this ^= *finalkey;
		buff.final(*this);
		Block::cast(&tag) = v;
	}
};
}}
