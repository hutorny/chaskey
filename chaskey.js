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
	this.raw = function() {
		return Uint8Array.from(v.buffer);
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
	this.cast = function(block) {
		var res = new ChaskeyCipher(this.block_t, this.N);
		res.v
		return res;
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
		if( typeof(message) === typeof("") || message instanceof String ) try {
			message = new TextEncoder("utf-8").encode(message);
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
		bytes.set(new Uint8Array(data.buffer), pos);
		return (pos += N) < bytes.length;		
	}
	this.full = function() {
		return pos + N <= bytes.length;
	}
	this.bytes = function() {
		return Uint8Array.from(bytes.subarray(0,pos));
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
		cipher.permute(block);
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
		cipher.permute(block);
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

/** ChaskeyCipher.Mac - a predefined primitive MAC using ChaskeyCipher */
ChaskeyCipher.Mac = function(count) {
	Mac.call(this, new ChaskeyCipher(block32x4, count||8));
}

/** ChaskeyCipher.Cbc - a predefined primitive CBC using ChaskeyCipher */
ChaskeyCipher.Cbc = function(count) {
	Cbc.call(this, new ChaskeyCipher(block32x4, count||8));
}


/** patching IE 																*/ 
if( ! Uint32Array.from ) {
	Uint32Array.from = function(src) {
		var dst = new Uint32Array(src.length);
		Array.prototype.every.call(dst, function(v,i) { dst[i] = src[i]; return true; });
		return dst;
	}
}
if( ! Uint8Array.from ) {
	Uint8Array.from = function(src) {
		var dst = new Uint8Array(src.length);
		Array.prototype.every.call(dst, function(v,i) { dst[i] = src[i]; return true; });
		return dst;
		
	}
}
if( ! Uint8Array.prototype.fill ) {
	Uint8Array.prototype.fill = function(val) {
		Array.prototype.every.call(this, function(v,i) { this[i] = val; return true; });
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
