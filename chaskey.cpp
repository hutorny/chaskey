/**
 * Drop-in replacement for reference implementation of Chaskey MAC algorithm
 * invented by Nicky Mouha http://mouha.be/chaskey/
 */

#include <assert.h>
#include "chaskey.hpp"
#ifndef CHASKEY_HEAD2HEAD_TEST
#include "chaskey.h"
#endif

namespace crypto {
namespace chaskey {
/** single chunk formatter to optimize access to a single chunk of data */
template<bool = details::arch_traits::direct_safe>
class single_chunk;

/* little-endian version with direct access	to the data					*/
template<>
class single_chunk<true> : public details::simple_formatter<uint32_t,4> {
public:
	typedef details::simple_formatter<uint32_t,4> base;
	using typename base::block_t;
	using typename base::size_t;
	inline void attach(const uint8_t* msg, size_t len) noexcept {
		size_t blocks = len ? (len - 1) / sizeof(block_t) : 0;
		raw = reinterpret_cast<const block_t*>(msg);
		end = raw + blocks;
		size_t tail = (len % sizeof(block_t));
		if( tail || ! len ) {
			msg += len - tail;
			base::append(msg, tail); /* side effect on tail and msg */
			base::pad(1);
			las = &base::block();
			padded = true;
		} else {
			las = raw + blocks;
			padded = false;
		}
	}
	inline const block_t& block() const noexcept {
		return *raw;
	}
	inline void reset() noexcept {
		base::reset();
		raw = &base::block();
	}
	inline void next() noexcept {
		raw++;
	}
	inline const block_t& last() noexcept {
		return *las;
	}
	/* returns true if has more that one block to process				*/
	inline bool has() const noexcept {
		return raw < end;
	}
	inline bool pad() const noexcept {
		return padded;
	}
private:
	const block_t* raw;
	const block_t* end;
	const block_t* las;
	bool padded;
};


/* big-endian full-buffered	version											*/

template<>
class single_chunk<false> : public details::simple_formatter<uint32_t,4> {
public:
	typedef details::simple_formatter<uint32_t,4>  base;
	using typename base::block_t;
	using typename base::size_t;
	inline void attach(const uint8_t* amsg, size_t alen) noexcept {
		msg=amsg;
		len = alen;
		base::append(msg, len);
	}
	inline void next() noexcept {
		reset();
		base::append(msg, len);
	}
	inline const block_t& last() noexcept {
		return base::block();
	}
	inline bool has() const noexcept {
		return len;
	}
	inline bool pad() noexcept {
		if( full() ) return false;
		base::pad(1);
		return true;
	}
private:
	const uint8_t* msg;
	size_t len;
	bool padded;
};

/**
 * Chaskey8Alt - implements Chaskey message authentication algorithm
 * 			optimized to work with single chunk of data
 */
class Chaskey8Alt : public Chaskey8 {
public:
	typedef uint8_t tag_t[sizeof(block_t)];
	/**
	 * computes message digest, and writes results to tag
	 */
	void sign(tag_t& tag, const uint8_t* msg, uint_fast16_t len,
			const block_t& key,	const block_t& subkey1,
			const block_t& subkey2) noexcept {
		single_chunk<> buff;
		init(key);
		buff.attach(msg, len);
		const block_t* finalkey = &subkey1;
		while( buff.has() ) {
			*this ^= buff.block();
			permute();
			buff.next();
		};
		if( buff.pad() )
			finalkey = &subkey2;
		*this ^= buff.last();
		*this ^= *finalkey;
		permute();
		*this ^= *finalkey;
		buff.final(*this);
		Block::cast(&tag) = v;
	}
};
}}
using namespace crypto::chaskey;

inline const Chaskey8::block_t& cast(const uint32_t *key) noexcept {
	return * reinterpret_cast<const Chaskey8::block_t*>(key);
}
inline Chaskey8::block_t & cast(uint32_t *key) noexcept {
	return * reinterpret_cast<Chaskey8::block_t*>(key);
}
__attribute__((weak))
void subkeys(uint32_t k1[4], uint32_t k2[4], const uint32_t k[4]) {
	const Chaskey8::block_t & key(cast(k));
	Chaskey8::Block & key1(Chaskey8::cast(k1));
	Chaskey8::Block & key2(Chaskey8::cast(k2));
	Chaskey8::derive(key1, key);
	Chaskey8::derive(key2, key1);
}

__attribute__((weak))
void chaskey(uint8_t *tag, uint32_t taglen, const uint8_t *m, const uint32_t mlen,
		const uint32_t k[4], const uint32_t k1[4], const uint32_t k2[4]) {
	assert(taglen<=sizeof(Chaskey8::tag_t));
	Chaskey8Alt cipher;
	cipher.sign(*reinterpret_cast<Chaskey8::tag_t*>(tag), m, mlen,
			cast(k), cast(k1), cast(k2));
}

void (*chaskey_cpp)(uint8_t *, uint32_t, const uint8_t *, const uint32_t,
		const uint32_t [4], const uint32_t [4], const uint32_t [4]) = &chaskey;

void (*subkeys_cpp)(uint32_t [4], uint32_t [4], const uint32_t [4]) = &subkeys;
