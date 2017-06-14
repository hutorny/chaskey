/* chaskey.js - a JS implementation of Chaskey algorithm in MAC and CBC modes
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

/**
  * creates a new block, 32x4 bits, copies content from a, if compatible
  */
function block32x4(a) {
	var N = 4;
	this.v = a ? Uint32Array.from(a) : new Uint32Array(N);
	this.xor = function(blk) {
		for(var i in this.v) {  this.v[i] ^= (blk.v||blk)[i]; }
	}
	this.xor_bytes = function(blk, size) {
		var v = new Uint8Array(this.v.buffer);		
		var b = blk.v 
			? new Uint8Array(blk.v.buffer, blk.v.byteOffset)
			: new Uint8Array(blk.buffer, blk.byteOffset);
		for(var i = 0; i<size; ++i) {  v[i] ^= b[i]; }
	}
	this.raw = function() {
		return Uint8Array.from(this.v.buffer);
	}
	this.assign = function(b) {
		var v = new DataView(b);		
		for(var i in this.v){
			this.v[i] = v.getUint32(i, true);	
		}
	}
	this.array = function() {
		return Array.from(this.v);
	}
	this.block = function() {
		return this.v;
	}
	this.assign = function(a) {
		this.v.set(a.v||a);
	}
	this.size = N * Uint32Array.BYTES_PER_ELEMENT;
 }
 
 /**
  * Constructs a new Chasky Cipher operating on block with <count> rounds
  * of transformations 
  */
 function ChaskeyCipher(block, count) {
	block.call(this);
	var N = count;
	this.block_t = block;
	function ror(val, n) {
		return (val << (32-n)) | (val >>> n);
	}

	function rol(val, n) {
		return (val >>> (32-n)) | (val << n);
	}
	this.round =  function() {
		var v = this.block();
		v[0] += v[1];
		v[1]  = rol(v[1], 5);
		v[1] ^= v[0];
		v[0]  = rol(v[0],16);
		v[2] += v[3];
		v[3]  = rol(v[3], 8);
		v[3] ^= v[2];
		v[0] += v[3];
		v[3]  = rol(v[3],13);
		v[3] ^= v[0];
		v[2] += v[1];
		v[1]  = rol(v[1], 7);
		v[1] ^= v[2];
		v[2]  = rol(v[2],16);	
	}
	
	this.dnour = function(v)  {
		//var v = this.block();
		v[2]  = ror(v[2],16);
		v[1] ^= v[2];
		v[1]  = ror(v[1], 7);
		v[2] -= v[1];
		v[3] ^= v[0];
		v[3]  = ror(v[3],13);
		v[0] -= v[3];
		v[3] ^= v[2];
		v[3]  = ror(v[3], 8);
		v[2] -= v[3];
		v[0]  = ror(v[0],16);
		v[1] ^= v[0];
		v[1]  = ror(v[1], 5);
		v[0] -= v[1];
	}
	this.permute = function() {
		for(var i = N; i--; ) {
			this.round();
		}
	}
	this.etumrep = function(v) {
		for(var i = N; i--; ) {
			this.dnour(v);
		}
	}
	this.derive = function(i) {
		i = i.v || i;
		return new this.block_t([
			(i[0] << 1) ^((i[3] >>  31) & 0x87), /* >> for signed shift */
			(i[1] << 1) | (i[0] >>> 31),
			(i[2] << 1) | (i[1] >>> 31),
			(i[3] << 1) | (i[2] >>> 31)]);
	}
	this.init = function(key) {
		this.assign(key);
	}
	this.clone = function() {
		return new ChaskeyCipher(this.block_t, N);
	}
};

/**
 * Constructs a new block formatter, n specifies blok length in bytes
 */
function Formatter(n) {
	var N = n;
	var bytes = new Uint8Array(new ArrayBuffer(N));
	var pos = 0;
	var len = 0;
	
	this.init = function(n) {
		N = n;
		bytes = new Uint8Array(new ArrayBuffer(N));
		patch4IE(bytes);
		pos = 0;
		len = 0;		
	} 	
	this.reset = function() {
		bytes.fill(0);
		pos = 0;
		len = 0;		
	}
	function resize(l) {
		var res = new Uint8Array(new ArrayBuffer(l));
		res.set(bytes);
		bytes = res;
		patch4IE(bytes);
	}
	
	/* https://github.com/feross/buffer/issues/60 							*/
	function utf8ToBinaryString(str) {
		  var escstr = encodeURIComponent(str);
		  // replaces any uri escape sequence, such as %0A, with binary escape, such as 0x0A
		  var binstr = escstr.replace(/%([0-9A-F]{2})/g, function(match, p1) {
		    return String.fromCharCode('0x' + p1);
		  });

		  return binstr;
		}

	function utf8ToBuffer(str) {
	  var binstr = utf8ToBinaryString(str);
	  var buf = new Uint8Array(binstr.length);
	  Array.prototype.forEach.call(binstr, function (ch, i) {
	    buf[i] = ch.charCodeAt(0);
	  });
	  return buf;
	}
	
	
	this.append = function(message) {
		if( typeof(message) === typeof("") || message instanceof String) try {
			if( window.TextEncoder )
				message = new TextEncoder("utf-8").encode(message);
			else
				message = utf8ToBuffer(message);
		} catch(e) { 
			console.log(e);
			message = utf8ToBuffer(message);
		}
		if( !(message instanceof Uint8Array) ) 
			throw Error("Message is not a byte string (Uint8Array or String)");
		var l = len + message.length;
		if( l > bytes.length ) {
			resize(l + ((l % N) ? N - (l % N) : 0));
		}
		bytes.set(message, len);
		len += message.length;
	}
	this.pad = function(firstbyte) {
		if( len && len == bytes.length ) return false;
		while(len < bytes.length ) {
			bytes[len++] = firstbyte;
			firstbyte = 0;
		}
		return true;
	}
	this.last = function() {
		return pos + N >= bytes.length;		
	}
	this.block = function() {
		return new Uint32Array(bytes.buffer, pos, N/Uint32Array.BYTES_PER_ELEMENT);		
	}
	this.next = function(data) {
		return (pos += N) < bytes.length;		
	}	
	this.move = function(data) {
		data && this.save(data);
		return (pos += N) < bytes.length;		
	}
	this.save = function(data) {
		bytes.set(new Uint8Array(data.buffer), pos);
	}
	this.full = function() {
		return pos + N <= len;
	}
	this.bytes = function(l) {
		return Uint8Array.from(bytes.subarray(0,l||len));
	}
	this.len = function() {
		return len;
	}
}

/**
 * Constructs a MAC crypto primitive 
 */
function Mac(cipher, formatter) {	
	var key = null;
	var subkey1 = null;	
	var subkey2 = null;	
	var buff = formatter || new Formatter(cipher.size);
	formatter && formatter.init(cipher.size);	
	this.set = function(akey) {
		key = new cipher.block_t(akey);
		subkey1 = cipher.derive(key.block());
		subkey2 = cipher.derive(subkey1.block());
		cipher.init(key);
	}
	this.init = function () {
		cipher.init(key);
	}
	function encrypt(block) {
		cipher.xor(block);
		cipher.permute();
	}
	this.sign = function(message) {
		if( key === null ) throw new Error("key is not set");
		var finalkey = subkey1;
		cipher.init(key);
		buff.append(message);
		if ( buff.pad(1) ) finalkey = subkey2; 		
		do {
			if( buff.last() ) cipher.xor(finalkey);			
			encrypt(buff.block());
		} while(buff.next());
		cipher.xor(finalkey);			
		buff.reset();
		return new Uint8Array(cipher.block().buffer);
	}
}

/**
 * Constructs a Cbc crypto primitive 
 */
function Cbc(cipher, formatter) {
	var key = null;
	var buff = formatter || new Formatter(cipher.size);
	formatter && formatter.init(cipher.size);	
	this.set = function(akey) {
		key = new cipher.block_t(akey);
		cipher.init(key);
		buff.reset();		
	}
	function encrypt(block) {
		cipher.xor(block);
		cipher.permute();
		cipher.xor(key);
	}	
	function decrypt(input) {
		var output = new cipher.block_t(input);
		output.xor(key);
		cipher.etumrep(output.block());
		output.xor(cipher.block());
		cipher.init(input);
		return output.block();
	}	
	/** initialize the cipher with initialization vector iv					*/
	this.initIV = function(iv)  {
		cipher.init(key);
		cipher.xor(new cipher.block_t(iv));
		buff.reset();		
	}
	/** initialize the cipher with iv					*/
	this.init = function(nonce) {
		if( key === null ) throw new Error("key is not set");		
		/* NIST Special Publication 800-38a
		 * IV generation, recommended method number first.
		 * Apply the forward cipher function, under the same key that is
		 * used for the encryption of the plaintext, to a nonce				 */
		cipher.init(cipher.derive(key));
		buff.reset();
		buff.append(nonce);
		do {
			encrypt(buff.block());
		} while(buff.next());
		buff.reset();		
	}
	this.encrypt = function(message, last) {		
		if( key === null ) throw new Error("key is not set");		
		buff.append(message);		
		if( last !== false ) buff.pad(0);
		if(! buff.full() ) return new Uint8Array();
		do {
			encrypt(buff.block());
		} while( buff.move(cipher.block()) );
		return buff.bytes();
	}
	this.decrypt = function(message, last) {		
		if( key === null ) throw new Error("key is not set");		
		buff.append(message);		
		if(! buff.full() ) return new Uint8Array();
		while( buff.move(decrypt(buff.block())));
		return buff.bytes();
	}
}

/**
 * Constructs a Cloc crypto primitive 
 */
function Cloc(Cipher, formatter) {
	var key = null;
	var ozp = false;	
	var g1g2guard = false;
	var buff = formatter || new Formatter(Cipher.size);
	formatter && formatter.init(Cipher.size);
	var enc = Cipher;
	var tag = Cipher.clone();
	
	function asHex(b) {
		b = Array.from(b.v || b);
		return '[' + b.map(function(i){ return i.toString(16); }).join(",") + ']';
	} 

	function cipher(input) {
		if( input ) tag.xor(input);
		tag.permute();
		tag.xor(key);
	}
	
	function prf(tailsize, block) {
		block && enc.assign(block);
		tag.xor(key);
		cipher(enc);
		fix1(enc.block());
		enc.xor(key)
		enc.permute();
		tailsize == enc.size ? enc.xor(key) : enc.xor_bytes(key, tailsize);
	}
	
	/* CLOC-specific tweak function, 										*/
	/** f1(X) = (X[1, 3],X[2, 4],X[1, 2, 3],X[2, 3, 4])						*/
	function f1(b) {
		b[0]  ^= b[2];			/* X[1, 3]									*/
		var  t = b[1];
		b[1]  ^= b[3];			/* X[2, 4]									*/
		b[3]   = b[2] ^ b[1];	/* X[2, 3, 4]								*/
		b[2]   = b[0] ^ t;		/* X[1, 2, 3]								*/
	}
	/** f2(X) = (X[2],X[3],X[4],X[1, 2])									*/
	function f2(b) {
		var  t = b[0] ^ b[1];
		b[0]   = b[1];			/* X[2]										*/
		b[1]   = b[2];			/* X[2]										*/
		b[2]   = b[3];			/* X[4]										*/
		b[3]   = t;				/* X[1, 2]									*/
	}
	/** g1(X) = (X[3],X[4],X[1, 2],X[2, 3])									*/
	function g1(b) {
		var t  = b[0];
		b[0]   = b[2];			/* X[3]										*/
		b[2]   = b[1] ^ t;		/* X[1, 2]									*/
		t      = b[1];
		b[1]   = b[3];			/* X[4]										*/
		b[3]   = b[0] ^ t;		/* X[2, 3]									*/
	}
	/** g2(X) = (X[2],X[3],X[4],X[1, 2])									*/
	function g2(b) { f2(b); }
	/** h(X) = (X[1, 2],X[2, 3],X[3, 4],X[1, 2, 4]) 						*/
	function h(b) {
		b[0] ^= b[1]; 			/* X[1, 2]									*/
		b[1] ^= b[2];			/* X[2, 3]									*/
		b[2] ^= b[3];			/* X[3, 4]									*/
		b[3] ^= b[0];			/* X[1, 2, 4]								*/
	}
	function fix0(b) {
		var fixed = b[0] & 0x80000000;
		b[0] &= ~ 0x80000000;
		return !! fixed;
	}
	function fix1(b) {
		b[0] |= 0x80000000;
	}
	
	
	this.init = function() {
		ozp = false;	
		g1g2guard = false;
		enc.init(key);
		buff.reset();				
	}
	
	this.set = function(akey) {
		key = new enc.block_t(akey);
		this.init();
	}
	function update(block) {
		enc.xor(block);
		enc.permute();
		enc.xor(key);
	}	

	function process(block, tailsize, empty) {
		if( ! g1g2guard ) {
			if( empty ) g1(tag.block());
			else g2(tag.block());
			g1g2guard = true;
		}
		cipher();
		tailsize == enc.size ? enc.xor(block) : enc.xor_bytes(block, tailsize);
	}
	/** processes associated data  											*/
	this.update = function(message) {
		if( key === null ) throw new Error("key is not set");
		var fixed0 = false;
		buff.append(message);
		ozp = buff.pad(0x80);
		do {
			if( buff.last() ) fixed0 = fix0(enc.block());			
			update(buff.block());
			if( fixed0 ) h(enc.block());
		} while(buff.next());
		buff.reset();
	}

	/** applies a nonce														*/
	this.nonce = function(nonce) {
		if( key === null ) throw new Error("key is not set");		
		buff.append(nonce);
		buff.pad(0x80);
		enc.xor(buff.block());
		if( ozp ) f2(enc.block());
		else f1(enc.block());
		tag.assign(enc.block());
		enc.permute();
		enc.xor(key);
		buff.reset();
	}
	
	/** encrypts a chunk of data 											*/	
	this.encrypt = function(message, last) {
		if( key === null ) throw new Error("key is not set");		
		buff.append(message);
		last = ( last !== false );
		var len = buff.len();
		var tailsize = enc.size;
		if( last ) { 
			tailsize = (buff.len() % enc.size) || enc.size;
			buff.pad(0);
		}
		while( buff.full() ) {
			var tail = buff.last() ? tailsize : enc.size;
			process(buff.block(), tail, last && len == 0);
			buff.save(enc.block());
			prf(tail);
			buff.move();
		}
		return buff.bytes(len);
	}
	
	/** decrypts a chunk of data 											*/	
	this.decrypt = function(message, last) {		
		if( key === null ) throw new Error("key is not set");		
		buff.append(message);		
		last = ( last !== false );
		var len = buff.len();
		var tailsize = enc.size;
		if( last ) { 
			tailsize = (buff.len() % enc.size) || enc.size;
			buff.pad(0);
		}
		while( buff.full() ) {
			var input = Uint32Array.from(buff.block());
			var tail = buff.last() ? tailsize : enc.size;
			process(buff.block(), tail, last && len == 0);
			buff.move(enc.block());
			prf(tail, input);
		}
		return buff.bytes(len);
	}
	
	/** returns digest (MAC) chunk of data 									*/	
	this.mac = function() {
		return tag.raw();
	}
}

/** ChaskeyCipher.Mac - a predefined primitive MAC using ChaskeyCipher */
ChaskeyCipher.Mac = function(count) {
	Mac.call(this, new ChaskeyCipher(block32x4, count||8));
}

/** ChaskeyCipher.Cbc - a predefined primitive CBC using ChaskeyCipher */
ChaskeyCipher.Cbc = function(count) {
	Cbc.call(this, new ChaskeyCipher(block32x4, count||8));
}

ChaskeyCipher.Cloc = function(count) {
	Cloc.call(this, new ChaskeyCipher(block32x4, count||8));
}

/** patching IE 																*/ 
if( ! Uint32Array.from ) {
	Uint32Array.from = function(src) {
		var dst = new Uint32Array(src.length||0);
		Array.prototype.every.call(dst, function(v,i) { dst[i] = src[i]; return true; });
		return dst;
	}
}
if( ! Uint8Array.from ) {
	Uint8Array.from = function(src) {
		var dst = new Uint8Array(src.length||0);
		Array.prototype.every.call(dst, function(v,i) { dst[i] = src[i]; return true; });
		return dst;
		
	}
}
if( ! Uint8Array.prototype.fill ) {
	Uint8Array.prototype.fill = function(val) {
		Array.prototype.every.call(this, function(v,i) { this[i] = val; return true; });
	}	
}

if( ! Array.from ) {
	Array.from = function(src) {
		var dst = new Array(src.length);
		dst.every(function(v,i) { dst[i] = src[i]; return true; });
		return dst;
	}
}

function patch4IE(obj) {
	if( !obj.subarray )
		obj.subarray = function(b,e) {
			return Uint8Array.from(Array.prototype.slice.call(this,b,e));
		};
	return obj;
}

/*  patching IE 																*/ 
