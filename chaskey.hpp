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
 * crypto::chaskye::Chaskey8
 * crypto::chaskye::Cipher8::Mac
 * crypto::chaskye::Cipher8::Cbc
 * crypto::chaskye::Cipher8::Cloc
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

namespace details {
	inline bool equals(const void* a, const void* b, uint_fast8_t len) noexcept {
		const uint8_t* l { reinterpret_cast<const uint8_t*>(a) };
		const uint8_t* r { reinterpret_cast<const uint8_t*>(b) };
		uint8_t res = 0;
		while(len--) res |= l[len] ^ r[len];
		return res == 0;
	}
}

/**
 * BlockCipher in the Cipher Block Chaining Mode (CBC)
 * In this mode BlockCipher is used to encrypt and decrypt messages
 * http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
 * chapter 6.2
 *
 * Usage:
 * 		Cbc<Cipher,Formatter> cbc;
 * 		cbc.set(key);
 * 		cbc.init(nonce, length); 				// feed nonce
 * 		cbc.encrypt(out, datachunk, false);		// feed data by chunks
 * 		cbc.encrypt(out, lastdatachunk, true);	// feed last data chunk
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
		buff.reset();
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
 *
 * Usage:
 * 		Mac<Cipher,Formatter> mac;
 * 		mac.set(key);
 * 		mac.init(); 							// when reusing instance
 * 		mac.update(datachunk, false);			// feed data by chunks
 * 		mac.update(lastdatachunk, true);		// feed last data chunk
 * 		mac.write(out);							// write computed tag to out
 * 		mac.verify(tag, taglen);				// or verify tag
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
	inline void init() noexcept {
		Cipher::init(key);
		buff.reset();
	}
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
					if( ! buff.full() ) return;
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
	/**
	 * writes computed MAC to output
	 * if all 16 bytes are not needed, use a stream that trims
	 */
	template<class stream>
	inline void write(stream&& output) const noexcept {
		output.write(reinterpret_cast<const char*>(Cipher::raw()),Cipher::size());
	}
	/**
	 * verifies computed MAC against provided externally tag
	 */
	inline bool
	verify(const void* tag,uint_fast8_t len=sizeof(block_t)) const noexcept {
		return details::equals(Cipher::raw(), tag,
			len < sizeof(block_t) ? len : sizeof(block_t));
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

/**
 * BlockCipher in CLOC Mode https://eprint.iacr.org/2014/157.pdf [157]
 * In this mode CBC is used to provide both authentication and encryption
 *
 * Usage:
 * 		Cloc<Cipher,Formater> cloc;
 * 		cloc.set(key);
 * 		cloc.init(); 							// when reusing instance
 * 		cloc.update(adchunk, length, false);	// feed AD by chunks
 * 		cloc.update(lastadchunk, length, true); // feed last AD chunk
 * 		cloc.nonce(nonce, length);				// feed noce
 * 		cloc.encrypt(out, datachunk, false);	// feed data by chunks
 * 		cloc.encrypt(out, lastdatachunk, true);	// feed last data chunk
 */
template<class Cipher, class Formatter>
class Cloc {
public:
	using Block   = typename Cipher::Block;
	using item_t  = typename Block::item_t;
	using block_t = typename Cipher::block_t;
	using size_t = uint_fast16_t;		/* not expecting chunks larger 64K  */
	inline Cloc() noexcept {}
	inline Cloc(const Cloc&) = delete; 	/* no copy constructor 				*/
	explicit inline Cloc(const block_t&& _key) noexcept  { set(_key); }
	explicit inline Cloc(const block_t& _key) noexcept { set(_key); }

	/** sets the secret key to use 											*/
	inline void set(const block_t& _key) noexcept {
		key = _key;
		init();
	}
	/**
	 * Initializes vector by running forward cipher function on nonce
	 */
	inline void init() noexcept {
		enc       = key;
		ozp       = false;
		finalized = false;
		fix0guard = false;
		g1g2guard = false;
		nonceguard = false;
		buff.reset();
	}
	/** Processes chunk of associated data msg of length len,
	 *  final finishes generation by padding the message to the size of
	 *  block and applying one of derived keys.
	 *  Corresponds to the first part of HASH, see Fig 3 of [157]			*/
	inline void update(const uint8_t* msg, size_t len, bool final) noexcept {
		do {
			buff.append(msg, len);
			if( ! len ) {
				if( ! buff.full() ) {
					if( final )
						ozp = buff.pad(0x80);		/* apply ozp 			*/
					else
						return;
				}
			}
			bool fixed0 = !fix0guard && fix0(enc);
			update(buff.block());
			fix0guard = true;
			if( fixed0 ) h(enc);
			buff.reset();
		} while( len );
	}
	/** Processes nonce monce of length len in one chunk
	 *  Corresponds to the last part of HASH, see Fig 3 of [157]			*/
	inline void nonce(const uint8_t* monce, size_t len) {
		/* if buffer is not empty call update for final block				*/
		if( buff.available() ) update(monce,0,true);
		if( monce )	buff.append(monce, len);
		buff.pad(0x80);								/* apply ozp 			*/
		enc ^= buff.block();
		if( ozp ) f2(enc);
		else f1(enc);
		tag = enc;
		enc.permute();		/* corresponds to V->EK on fig.4				*/
		enc ^= key;
		buff.reset();
		nonceguard = true;
	}
	/**
	 * Encrypts message msg of length len and writes it to the output stream
	 * if final == true, the message is padded o the size of block
	 */
	template<class stream>
	inline void encrypt(stream&& output, const uint8_t* msg, size_t len, bool final) noexcept {
		if( ! nonceguard ) nonce(nullptr,0);
		do {
			uint_fast8_t size;
			if( ! (size = process(msg, len, final)) ) return;
			const block_t& result = buff.result(enc);
			output.write(reinterpret_cast<const char*>(result), size);
			prf(false, size);
			buff.reset();
		} while( len );
	}

	/**
	 * Decrypts ciphertext msg of length len and writes it to the output stream
	 * if final == true, the message is padded o the size of block
	 */
	template<class stream>
	inline void decrypt(stream&& output, const uint8_t* msg, size_t len, bool final) noexcept {
		Formatter buf;
		if( ! nonceguard ) nonce(nullptr,0);
		do {
			uint_fast8_t size;
			if( ! (size = process(msg, len, final)) ) return;
			const block_t& result = buf.result(enc);
			output.write(reinterpret_cast<const char*>(result), size);
			prf(true, size);
			buff.reset();
		} while( len );
	}
	/**
	 * writes computed MAC to output
	 * if all 16 bytes are not needed, use a stream that trims
	 */
	template<class stream>
	void write(stream&& output) const noexcept {
		finalize();
		output.write(reinterpret_cast<const char*>(tag.raw()),Cipher::size());
	}
	/**
	 * verifies computed MAC against provided externally tag
	 */
	inline bool
	verify(const void* _tag, uint_fast8_t len=sizeof(block_t)) const noexcept {
		finalize();
		return details::equals(tag, _tag,
			len < sizeof(block_t) ? len : sizeof(block_t));
	}

protected:
	inline void finalize() const  noexcept {
		if( ! finalized ) {
			Formatter::final(tag);
			finalized = true;
		}
	}
	inline void update(const block_t& input) noexcept {
		enc  ^= input;
		enc.permute();
		enc  ^= key;
	}
	inline void cipher() noexcept {
		tag.permute();
		tag  ^= key;
	}
	inline bool nodata(bool final) noexcept {
		if( final ) {
			if( ! g1g2guard && ! buff.available() ) {
				g1(tag);
				cipher();
			} else {
				buff.pad(0);
				return false;
			}
		}
		return true;
	}
	inline void apply_g2() noexcept {
		g2(tag);
		cipher();
		g1g2guard = true;
	}

	inline uint_fast8_t process(const uint8_t*& msg, size_t& len, bool final) noexcept {
		buff.append(msg, len);
		uint_fast8_t size = buff.available();
		if( ! buff.full() && nodata(final) ) return 0;

		if( ! g1g2guard ) { /* g2 guard */
			apply_g2();
		}
		if( size == sizeof(block_t) )
			enc ^= buff.block();  /* enc contains a block of cipher text 		*/
		else
			Formatter::xor_bytes(enc.raw(), buff.block(), size);
		return size;
	}
	inline void prf(bool decrypt, uint_fast8_t size) noexcept {
		if( decrypt ) enc = buff.block();
		if( size == sizeof(block_t) )
			tag ^= enc;
		else
			Formatter::xor_bytes(tag.raw(), enc, size);
		tag ^= key;
		cipher();
		if( size != sizeof(block_t) ) return;
		fix1(enc);
		enc ^= key;
		enc.permute();
		enc ^= key;
	}
private:
	/* CLOC-specific tweak function, chapter 3, [157]						*/
	/* Courtesy to Markku-Juhani O. Saarinen (mjosaarinen)					*/
	/* https://github.com/mjosaarinen/brutus/tree/master/crypto_aead_round1/aes128n12clocv1/ref */
	/** f1(X) = (X[1, 3],X[2, 4],X[1, 2, 3],X[2, 3, 4])						*/
	static inline void f1(block_t& b) noexcept {
		b[0]  ^= b[2];			/* X[1, 3]									*/
		auto t = b[1];
		b[1]  ^= b[3];			/* X[2, 4]									*/
		b[3]   = b[2] ^ b[1];	/* X[2, 3, 4]								*/
		b[2]   = b[0] ^ t;		/* X[1, 2, 3]								*/
	}
	/** f2(X) = (X[2],X[3],X[4],X[1, 2])									*/
	static inline void f2(block_t& b) noexcept {
		auto t = b[0] ^ b[1];
		b[0]   = b[1];			/* X[2]										*/
		b[1]   = b[2];			/* X[2]										*/
		b[2]   = b[3];			/* X[4]										*/
		b[3]   = t;				/* X[1, 2]									*/
	}
	/** g1(X) = (X[3],X[4],X[1, 2],X[2, 3])									*/
	static inline void g1(block_t& b) noexcept {
		auto t = b[0];
		b[0]   = b[2];			/* X[3]										*/
		b[2]   = b[1] ^ t;		/* X[1, 2]									*/
		t      = b[1];
		b[1]   = b[3];			/* X[4]										*/
		b[3]   = b[0] ^ t;		/* X[2, 3]									*/
	}
	/** g2(X) = (X[2],X[3],X[4],X[1, 2])									*/
	static inline void g2(block_t& b) noexcept { f2(b); }
	/** h(X) = (X[1, 2],X[2, 3],X[3, 4],X[1, 2, 4]) 						*/
	static inline void h(block_t& b) noexcept {
		b[0] ^= b[1]; 			/* X[1, 2]									*/
		b[1] ^= b[2];			/* X[2, 3]									*/
		b[2] ^= b[3];			/* X[3, 4]									*/
		b[3] ^= b[0];			/* X[1, 2, 4]								*/
	}
	static inline bool fix0(block_t& b) noexcept {
		bool fixed = b[0] & (static_cast<item_t>(1)<<31);
		b[0] &= ~(static_cast<item_t>(1)<<31);
		return fixed;
	}
	static inline void fix1(block_t& b) noexcept {
		b[0] |= static_cast<item_t>(1)<<31;
	}

private:
	Block key;
	Formatter buff;
	Cipher enc;				/* encryption cipher state 						*/
	mutable Cipher tag;		/* tag processing cipher state 					*/
	bool g1g2guard;			/* true, if g1 or g2 has been applied			*/
	bool fix0guard;			/* true, if fix0 has been applied				*/
	bool nonceguard;		/* true, if nonce() has been called				*/
	bool ozp;				/* associated data were OZP padded				*/
	mutable bool finalized;	/* tag has been reordered as little endian		*/
};


namespace details {

struct arch_traits {
	/* free standing constexpr not yet available,
	 * therefore it has to be placed inside  a struct 						*/
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
static inline constexpr T rol(T x, uint_fast8_t N) {
	return (x >> (sizeof(T)*8 - N)) | ((x) << (N));
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
	inline bool pad(uint8_t chr) noexcept {
		bool padded = false;
		while( pos < sizeof(data.b) ) {
			data.b[endian<>::index<sizeof(T)>(pos++)] = chr;
			chr = 0;
			padded = true;
		}
		return padded;
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
	inline static void
	xor_bytes(uint8_t* state, const void* ptr, uint_fast8_t len) noexcept {
		const uint8_t* bytes = reinterpret_cast<const uint8_t*>(ptr);
		uint_fast8_t i = 0;
		while(len--) {
			state[details::endian<>::index<4>(i)] ^=
					bytes[details::endian<>::index<4>(i)];
			++i;
		}
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
	static inline void
	xor_bytes(uint8_t* state, const void* ptr, uint_fast8_t len) noexcept {
		const uint8_t* bytes = reinterpret_cast<const uint8_t*>(ptr);
		while(len--) *state++ ^= *bytes++;
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
	inline bool operator==(const block_t& val) const noexcept {
		bool res = true;
		for(auto i = N; i--; ) res &= v[i] == val[i];
		return res;
	}
	inline bool operator!=(const block_t& val) const noexcept {
		bool res = false;
		for(auto i = N; i--; ) res |= v[i] != val[i];
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
		static_assert(&(static_cast<const block*>(nullptr)->v)==nullptr,
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
	using Cloc= crypto::Cloc<Cipher,details::block_formatter<item_t,count>>;

	using base::operator=;
	using base::operator==;
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
class Cipher8 : public Cipher<8> {
public:
	static unsigned constexpr count = chaskey::Cipher<8>::count; /* == 4 */
	using base::operator=;
};

/**
 * Cipher8s - implements Chaskey8 with not-inlined permutations
 * With many instantiations of cipher it may significantly reduce code size
 */
class Cipher8s : public Cipher<8> {
public:
	typedef Cipher<8> base;
	static unsigned constexpr count = base::count; /* == 4 */
	using base::block_t;
	using base::Block;
	using Cbc = crypto::Cbc<Cipher8s,details::block_formatter<item_t,count>>;
	using Mac = crypto::Mac<Cipher8s,details::block_formatter<item_t,count>>;
	using Cloc= crypto::Cloc<Cipher8s,details::block_formatter<item_t,count>>;

	using base::operator=;
	using base::operator==;
	void permute() noexcept;
	void etumrep() noexcept;
	static void derive(block_t& v, const block_t& in) noexcept;
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
