function ChaskeyTests() {

	function block2hex(blk) {
		if( ! (blk instanceof Uint32Array ) ) blk = new Uint32Array(blk.buffer||blk);  
		return Array.prototype.map.call(blk, function(v) { 
			return '0x'+('0000000' + v.toString(16)).slice(-8); 
		}).join(',');
	}
	
	function bytes2hex(blk, dlm) {
		 return Array.prototype.map.call(new Uint8Array(blk.buffer||blk), 
				 function(s){ return ('00' + s.toString(16)).slice(-2); }).join(dlm||'');	
	}

	function logblock(msg, blk) {
		console.log(msg.toString() + block2hex(blk));
	}

	
	this.loglevels = "fail,error,info,debug";

	
	function compare(a,b,n) {
		return Array.prototype.every.call(a, function(v, i){ return v === b[i] || i >= n; });
	}

	function string2bytes(str) {
		return Array.prototype.map.call(new Uint8Array(str.length),function(v,i) { return str.charCodeAt(i); }); 
	}
	
	function bytes2string(str) { 
		return Uint8Array.from(str.match(/.{1,2}/g).map(function(v) {return parseInt(v, 16); })); 
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
	
	function bufferToUtf8(arr) {
		return decodeURIComponent(escape(Array.prototype.map.call(arr, function(c) { return String.fromCharCode(c); }).join('')));
	}
	
	function log(clas, msg) {
		var div = document.createElement('div');
		div.setAttribute('class',clas);
		div.innerHTML = Array.prototype.map.call(msg, function(i) {
				return "<span>" + i + "</span>";
			}).join('');
		document.body.appendChild(div)
	}
	
	function generatePseudoRandomKey(func) {
		var key = new Uint8Array(16);
		Array.prototype.every.call(key, function(v,i) {
			key[i] = Math.random() * 256;
			return true;
		});
		func(key);
	}

	
	function generateRandomCryptoKey(func) {
		window.crypto.subtle.generateKey({name:"AES-CBC",length:128},true, ["encrypt"])
			.then(function(v) {
		window.crypto.subtle.exportKey("raw",v)
			.then(func);}).catch(function(e) {
				console.log('Fallback to pseaudo-random because "' +  e.message + '"');
				generatePseudoRandomKey(func); 
		} );
	}
	
	function generateRandomKey(func) {
		if( window.crypto && window.crypto.subtle )
		try {
			return generateRandomCryptoKey(func);
		} catch(err) {
			console.log(err.message);
		}
		generatePseudoRandomKey(func);
	}
	
	this.demo = function() {
		this.ui = {
			mode		: '#mode',
			key			: '#key',
			data		: '#data',
			nonce		: '#nonce',
			message		: '#message',
			ciphertext	: '#ciphertext',
			encrypt		: '#encrypt',
			decrypt		: '#decrypt',
			sign		: '#sign',
			format		: '#format'
		};
		var validmodes = {
			nonce		: ['CBC','CLOC'],
			data		: ['CLOC'],
			encrypt		: ['CBC','CLOC'],
			decrypt		: ['CBC','CLOC'],
			sign		: ['MAC','CLOC']
		}
		var ui = this.ui;
		Object.keys(ui).every(function(id) {
			ui[id] = document.querySelector(ui[id]);
			return true;
		});
		var backend = this;
		backend.ui = ui;
		
		this.ui.encrypt.onclick = function() {
			backend.encrypt(ui.mode.value);
		}
		this.ui.decrypt.onclick = function() {
			backend.decrypt(ui.mode.value);
		}
		this.ui.sign.onclick = function() {
			backend.sign(ui.mode.value);
		}
		this.ui.format.onchange = function() {
			backend.formatchange();
		}
		this.ui.ciphertext.onchange = function() {
			this.format = null;
		}
		this.ui.mode.onchange = function() {
			var value = this.value;
			Object.keys(validmodes).every(function(id){
				ui[id].disabled = validmodes[id].indexOf(value) < 0;
				return true;
			});
		}
		if( !this.ui.key.value ) {
			generateRandomKey(function(key) {
				backend.renderKey(key);
			});
		}
		try { this.encoder = new TextEncoder('utf-8'); }
		catch(e) {
			console.log(e);
			this.encoder = { encode : utf8ToBuffer };
		}
		try { this.decoder = new TextDecoder('utf-8'); }
		catch(e) {
			console.log(e);
			this.decoder = { decode : bufferToUtf8 };
		}		
		this.zero = this.decoder.decode(Uint8Array.from([0]))
	}
	
	this.renderKey = function(key) {
		this.ui.key.value = bytes2hex(key,'').toUpperCase();
	}
	
	function validByte(v,s) {
		if (v>=0 && v<=255) return v;
		throw new Error('Invalid key digit:' + s);
	}
	function validInt(v,s) {
		if (v>=0 && v<=0xFFFFFFFF) return v;
		throw new Error('Invalid key digit:' + s);
	}
	
	this.readKey = function() {
		var key = this.ui.key.value === '' ? [] : this.ui.key.value.split(',');
		if( key.length == 1 ) key = key[0].match(/.{1,2}/g);
		if( [4,16].indexOf(key.length) == -1 ) {
			throw new Error('Invalid key length:' + key.length);
		}
		if( key.length == 16) {
			key = key.map(function(v) { return validByte(parseInt(v, 16), v);	});
			return new Uint32Array(Uint8Array.from(key).buffer);
		}
		if( key.length == 4) {
			key = key.map(function(v) { return validInt(parseInt(v, 16), v);	});
			return Uint32Array.from(key);			
		}
		
	}

	this.encryptCBC = function(text) {
		var cbc = new ChaskeyCipher.Cbc();
		cbc.set(this.readKey());
		cbc.init(this.ui.nonce.value);
		return cbc.encrypt(this.encoder.encode(this.ui.message.value));		
	}

	this.encryptCLOC = function(text) {
		var cloc = new ChaskeyCipher.Cloc();
		cloc.set(this.readKey());
		cloc.update(this.ui.data.value);
		cloc.nonce(this.ui.nonce.value);
		return cloc.encrypt(text);
	}

	
	this.encrypt = function(mode) {
		try{
			var text = this.encoder.encode(this.ui.message.value);
			var cif = mode === 'CBC' ? this.encryptCBC(text) : this.encryptCLOC(text);
			
			if( this.ui.format.value === 'base-64' )
				this.ui.ciphertext.value = btoa(String.fromCharCode.apply(null, cif));
			else
				this.ui.ciphertext.value = bytes2hex(cif);

			this.ui.ciphertext.format = this.ui.format.value; 

		} catch(e) {
			this.error('ERROR:',e.message)
		}
	}

	this.decryptCBC = function(cif) {
		var cbc = new ChaskeyCipher.Cbc();
		cbc.set(this.readKey());
		cbc.init(this.ui.nonce.value);
		return cbc.decrypt(cif);
	}
	this.decryptCLOC = function(cif) {
		var cloc = new ChaskeyCipher.Cloc();
		cloc.set(this.readKey());
		cloc.update(this.ui.data.value);
		cloc.nonce(this.ui.nonce.value);
		return cloc.decrypt(cif);
	}

	this.decrypt = function(mode) {
		try{
			
			var format = this.ui.ciphertext.format || this.ui.format.value;
			var cif;
			
			if( format === 'base-64' )
				cif = Uint8Array.from(atob(this.ui.ciphertext.value).split('').map(function (c) { return c.charCodeAt(0); }));
			else
				cif = bytes2string(this.ui.ciphertext.value);
			var text = mode === 'CBC' ? this.decryptCBC(cif) : this.decryptCLOC(cif);
			this.ui.message.value =  this.decoder.decode(text).split(this.zero)[0];
		} catch(e) {
			this.error('ERROR:',e.message)
		}
	}

	this.signCLOC = function(text) {
		var mac = new ChaskeyCipher.Mac();
		mac.set(this.readKey());			
		return mac.sign(this.encoder.encode(text));		
	}

	this.signMAC = function(text) {
		var mac = new ChaskeyCipher.Mac();
		mac.set(this.readKey());			
		return mac.sign(this.encoder.encode(text));		
	}

	
	this.sign = function(mode) {
		try {
			var cif = mode === 'MAC' ? this.signMAC(this.ui.message.value) 
									 : this.signCLOC(this.ui.message.value);
			if( this.ui.format.value === 'base-64' )
				this.ui.ciphertext.value = btoa(String.fromCharCode.apply(null, cif));
			else
				this.ui.ciphertext.value = bytes2hex(cif);

			this.ui.ciphertext.format = this.ui.format.value; 

		} catch(e) {
			this.error('ERROR:',e.message)
		}
	}

	
	this.formatchange = function() {
		
	}
	
	this.run = function() {
		this.info('INFO :', 'Starting chaskey tests');
		if( this.test_MAC() )		
			this.info('PASS :', 'test_MAC');
		else
			this.fail('FAIL :', 'test_MAC');						
		if( this.test_CBC() )		
			this.info('PASS :', 'test_CBC');
		else
			this.fail('FAIL :', 'test_CBC');
		if( this.test_CLOC() )		
			this.info('PASS :', 'test_CLOC');
		else
			this.fail('FAIL :', 'test_CLOC');
	}
		
	this.test_MAC = function() {
		var k = [ 0x833D3433, 0x009F389F, 0x2398E64F, 0x417ACF39 ];
		var mac = new Mac(new ChaskeyCipher(block32x4, 8));
		var m = new Uint8Array(64);		
		var res = true;
		patch4IE(m);
		mac.set(k);
		
		for(var i=0; i < m.length; ++i) {
			m[i] = i;
			var tag = mac.sign(m.subarray(0,i));
			if( ! compare(new Uint32Array(tag.buffer), this.vectors[i]) ) {
				this.error("error: test_MAC        : length ",i);
				this.debug("got                    : ", block2hex(tag));
				this.debug("expected               : ", block2hex(this.vectors[i]));
				res = false;
			}
		}
		return res;
	}
	this.test_CBC = function() {
		var res = true;
		var cbc = new Cbc(new ChaskeyCipher(block32x4, 8));
		var plaintext = string2bytes(this.plaintext);
		patch4IE(plaintext);
		for(var i = 1; i < 64; ++i) {
			cbc.set(this.vectors[i]);
			cbc.initIV([0,0,0,0]);
			var msg = plaintext.subarray(0,i);
			var cif = cbc.encrypt(msg);
			if( ! compare(cif, this.masters[i-1]) ) {
				this.error("error: test_CBC/encrypt: ",this.plaintext.substr(0,i));
				this.debug("got                    : ", bytes2hex(cif));
				this.debug("expected               : ", bytes2hex(this.masters[i-1]));
				res = false;
			}
			cbc.initIV([0,0,0,0]);
			var txt = cbc.decrypt(cif);
			if( ! compare(txt, msg, i) ) {
				this.error("error: test_CBC/decrypt: ",  this.plaintext.substr(0,i));
				this.debug("got                    : ", bytes2hex(txt));
				this.debug("expected               : ", bytes2hex(msg));
				res = false;
			}
		}
		return res;
	}
	var nonce = "16  bytes  nonce";
	thiz = this;
	
	function test_cloc() {
		var res = true;
		var cloc = new Cloc(new ChaskeyCipher(block32x4, 8));
		var plaintext = string2bytes(thiz.plaintext);
		patch4IE(plaintext);
		var list = [7, 8, 9, 15, 16, 17, 31, 32, 33, 47, 48, 49, 50];
		for(var j in list) {
			var i = list[j];
			cloc.set(thiz.vectors[0]);
			cloc.update(plaintext.subarray(i%4,i+i%4), true);
			cloc.nonce(nonce);
			var msg = plaintext.subarray(i%6,i+i%6);
			var cif = cloc.encrypt(msg, true);
			cloc.init();
			cloc.update(plaintext.subarray(i%4,i+i%4), true);
			cloc.nonce(nonce);
			var txt = cloc.decrypt(cif, true);
			if( ! compare(txt, msg, i) ) {
				thiz.error("error:test_CLOC/decrypt: ", thiz.plaintext.substr(0,i));
				thiz.debug("got                    : ", bytes2hex(txt));
				thiz.debug("expected               : ", bytes2hex(msg));
				res = false;
			}
		}
		return res;		
	}

	function test_clocchunk() {
		var res = true;
		var cloc = new Cloc(new ChaskeyCipher(block32x4, 8));
		var verf = new Cloc(new ChaskeyCipher(block32x4, 8));
		var plaintext = string2bytes(thiz.plaintext);
		patch4IE(plaintext);
		var msglist = [15, 17, 1, 14, 13];
		cloc.set(thiz.vectors[0]);
		cloc.update(plaintext.subarray(0,18));
		cloc.nonce(nonce.substring(0,6));
		var out;
		var datalen = 0;
		for(var j in msglist) {
			var i = msglist[j];
			out = cloc.encrypt(plaintext.subarray(datalen, datalen+i), i == 13);			
			datalen += i;
		}
		verf.set(thiz.vectors[0]);
		verf.update(plaintext.subarray(0,18));
		verf.nonce(nonce.substring(0,6));
		var vrf = verf.encrypt(plaintext.subarray(0,datalen), true);
		if( ! compare(out, vrf, datalen) ) {
			thiz.error("error:test_CLOC/chunk  : ",  thiz.plaintext.substr(0,datalen));
			thiz.debug("got                    : ", bytes2hex(out));
			thiz.debug("expected               : ", bytes2hex(vrf));
			return false;
		}
		return true;
	}

	function test_clocmaster() {
		var res = true;
		var cloc = new Cloc(new ChaskeyCipher(block32x4, 8));
		var msg = string2bytes(thiz.plaintext);
		patch4IE(msg);
		for(var i = 0; i < 16; ++i) {
			cloc.set(thiz.vectors[i]);
			cloc.update(msg.subarray(i%5,i+i%5), i>=8);
			if( i < 8 )
				cloc.update(msg.subarray(i%5,16-i+i%5), true);
			cloc.nonce(msg.subarray(i,i+i+3));
			var out = cloc.encrypt(msg.subarray(0, i+8, i >= 8));
			if( i < 8 )
				out = cloc.encrypt(msg.subarray(i+8, i+i+8), true);
			var tmp = new Formatter(16);
			var len = i+8+(i<8?i:0);			
			tmp.append(out);
			tmp.append(cloc.mac());
			if( ! compare(tmp, thiz.masters[i+63], thiz.masters[i+63].length) ) {
				thiz.error("error:test_CLOC/master : ", thiz.plaintext.substr(0,len));
				thiz.debug("got                    : ", bytes2hex(tmp));
				thiz.debug("expected               : ", thiz.masters[i+63]);
				res = false;
			}
		}
		return res;
	}
	
	this.test_CLOC = function() {
		return !!(test_clocmaster() & test_cloc() & test_clocchunk()); 
	}
	
	
	this.fail = function() {
		console.log(Array.from(arguments).join(''));
		if( this.loglevels.indexOf('fail') >= 0 )		
			log('test-fail', arguments);
	}
	
	this.error = function() {
		console.log(Array.from(arguments).join(''));
		if( this.loglevels.indexOf('error') >= 0 )		
			log('test-error',arguments);
	}
	
	this.info = function() {
		console.log(Array.from(arguments).join(''));		
		if( this.loglevels.indexOf('info') >= 0 )		
			log('test-info',arguments);		
	}
	this.debug = function() {
		console.log(Array.from(arguments).join(''));		
		if( this.loglevels.indexOf('debug') >= 0 )		
			log('test-debug',arguments);		
	}
	
	this.plaintext = "Plain text message of sufficient length. Plain text message of sufficient length"
	
	this.vectors = [
		[ 0x792E8FE5, 0x75CE87AA, 0x2D1450B5, 0x1191970B ],
		[ 0x13A9307B, 0x50E62C89, 0x4577BD88, 0xC0BBDC18 ],
		[ 0x55DF8922, 0x2C7FF577, 0x73809EF4, 0x4E5084C0 ],
		[ 0x1BDBB264, 0xA07680D8, 0x8E5B2AB8, 0x20660413 ],
		[ 0x30B2D171, 0xE38532FB, 0x16707C16, 0x73ED45F0 ],
		[ 0xBC983D0C, 0x31B14064, 0x234CD7A2, 0x0C92BBF9 ],
		[ 0x0DD0688A, 0xE131756C, 0x94C5E6DE, 0x84942131 ],
		[ 0x7F670454, 0xF25B03E0, 0x19D68362, 0x9F4D24D8 ],
		[ 0x09330F69, 0x62B5DCE0, 0xA4FBA462, 0xF20D3C12 ],
		[ 0x89B3B1BE, 0x95B97392, 0xF8444ABF, 0x755DADFE ],
		[ 0xAC5B9DAE, 0x6CF8C0AC, 0x56E7B945, 0xD7ECF8F0 ],
		[ 0xD5B0DBEC, 0xC1692530, 0xD13B368A, 0xC0AE6A59 ],
		[ 0xFC2C3391, 0x285C8CD5, 0x456508EE, 0xC789E206 ],
		[ 0x29496F33, 0xAC62D558, 0xE0BAD605, 0xC5A538C6 ],
		[ 0xBF668497, 0x275217A1, 0x40C17AD4, 0x2ED877C0 ],
		[ 0x51B94DA4, 0xEFCC4DE8, 0x192412EA, 0xBBC170DD ],
		[ 0x79271CA9, 0xD66A1C71, 0x81CA474E, 0x49831CAD ],
		[ 0x048DA968, 0x4E25D096, 0x2D6CF897, 0xBC3959CA ],
		[ 0x0C45D380, 0x2FD09996, 0x31F42F3B, 0x8F7FD0BF ],
		[ 0xD8153472, 0x10C37B1E, 0xEEBDD61D, 0x7E3DB1EE ],
		[ 0xFA4CA543, 0x0D75D71E, 0xAF61E0CC, 0x0D650C45 ],
		[ 0x808B1BCA, 0x7E034DE0, 0x6C8B597F, 0x3FACA725 ],
		[ 0xC7AFA441, 0x95A4EFED, 0xC9A9664E, 0xA2309431 ],
		[ 0x36200641, 0x2F8C1F4A, 0x27F6A5DE, 0x469D29F9 ],
		[ 0x37BA1E35, 0x43451A62, 0xE6865591, 0x19AF78EE ],
		[ 0x86B4F697, 0x93A4F64F, 0xCBCBD086, 0xB476BB28 ],
		[ 0xBE7D2AFA, 0xAC513DE7, 0xFC599337, 0x5EA03E3A ],
		[ 0xC56D7F54, 0x3E286A58, 0x79675A22, 0x099C7599 ],
		[ 0x3D0F08ED, 0xF32E3FDE, 0xBB8A1A8C, 0xC3A3FEC4 ],
		[ 0x2EC171F8, 0x33698309, 0x78EFD172, 0xD764B98C ],
		[ 0x5CECEEAC, 0xA174084C, 0x95C3A400, 0x98BEE220 ],
		[ 0xBBDD0C2D, 0xFAB6FCD9, 0xDCCC080E, 0x9F04B41F ],
		[ 0x60B3F7AF, 0x37EEE7C8, 0x836CFD98, 0x782CA060 ],
		[ 0xDF44EA33, 0xB0B2C398, 0x0583CE6F, 0x846D823E ],
		[ 0xC7E31175, 0x6DB4E34D, 0xDAD60CA1, 0xE95ABA60 ],
		[ 0xE0DC6938, 0x84A0A7E3, 0xB7F695B5, 0xB46A010B ],
		[ 0x1CEB6C66, 0x3535F274, 0x839DBC27, 0x80B4599C ],
		[ 0xBBA106F4, 0xD49B697C, 0xB454B5D9, 0x2B69E58B ],
		[ 0x5AD58A39, 0xDFD52844, 0x34973366, 0x8F467DDC ],
		[ 0x67A67B1F, 0x3575ECB3, 0x1C71B19D, 0xA885C92B ],
		[ 0xD5ABCC27, 0x9114EFF5, 0xA094340E, 0xA457374B ],
		[ 0xB559DF49, 0xDEC9B2CF, 0x0F97FE2B, 0x5FA054D7 ],
		[ 0x2ACA7229, 0x99FF1B77, 0x156D66E0, 0xF7A55486 ],
		[ 0x565996FD, 0x8F988CEF, 0x27DC2CE2, 0x2F8AE186 ],
		[ 0xBE473747, 0x2590827B, 0xDC852399, 0x2DE46519 ],
		[ 0xF860AB7D, 0x00F48C88, 0x0ABFBB33, 0x91EA1838 ],
		[ 0xDE15C7E1, 0x1D90EFF8, 0xABC70129, 0xD9B2F0B4 ],
		[ 0xB3F0A2C3, 0x775539A7, 0x6CAA3BC1, 0xD5A6FC7E ],
		[ 0x127C6E21, 0x6C07A459, 0xAD851388, 0x22E8BF5B ],
		[ 0x08F3F132, 0x57B587E3, 0x087AD505, 0xFA070C27 ],
		[ 0xA826E824, 0x3F851E6A, 0x9D1F2276, 0x7962AD37 ],
		[ 0x14A6A13A, 0x469962FD, 0x914DB278, 0x3A9E8EC2 ],
		[ 0xFE20DDF7, 0x06505229, 0xF9C9F394, 0x4361A98D ],
		[ 0x1DE7A33C, 0x37F81C96, 0xD9B967BE, 0xC00FA4FA ],
		[ 0x5FD01E9A, 0x9F2E486D, 0x93205409, 0x814D7CC2 ],
		[ 0xE17F5CA5, 0x37D4BDD0, 0x1F408335, 0x43B6B603 ],
		[ 0x817CEEAE, 0x796C9EC0, 0x1BB3DED7, 0xBAC7263B ],
		[ 0xB7827E63, 0x0988FEA0, 0x3800BD91, 0xCF876B00 ],
		[ 0xF0248D4B, 0xACA7BDC8, 0x739E30F3, 0xE0C469C2 ],
		[ 0x67363EB6, 0xFAE8E047, 0xF0C1C8E5, 0x828CCD47 ],
		[ 0x3DBD1D15, 0x05092D7B, 0x216FC6E3, 0x446860FB ],
		[ 0xEBF39102, 0x8F4C1708, 0x519D2F36, 0xC67C5437 ],
		[ 0x89A0D454, 0x9201A282, 0xEA1B1E50, 0x1771BEDC ],
		[ 0x9047FAD7, 0x88136D8C, 0xA488286B, 0x7FE9352C ]
	];
	this.masters = [
		[ 222,202,68,203,71,185,154,219,88,87,129,165,229,233,20,84 ],
		[ 118,224,174,225,96,244,121,47,7,229,134,53,50,125,102,229 ],
		[ 181,138,189,126,50,202,139,119,242,229,175,10,166,232,171,135 ],
		[ 110,122,13,8,84,105,25,52,232,227,37,82,197,121,105,240 ],
		[ 152,133,195,170,129,159,115,98,75,234,31,71,144,111,76,123 ],
		[ 173,161,240,244,218,18,170,68,190,236,248,4,144,147,140,38 ],
		[ 208,231,42,190,67,254,150,98,203,135,73,122,146,167,113,229 ],
		[ 54,189,54,43,74,76,145,168,76,157,212,173,208,25,94,240 ],
		[ 31,72,238,18,104,238,139,142,45,85,187,193,182,105,38,5 ],
		[ 43,255,152,0,109,31,0,111,16,80,119,88,39,130,165,140 ],
		[ 94,178,192,27,86,56,148,42,195,180,12,94,61,200,52,150 ],
		[ 4,211,241,42,135,14,13,245,117,102,113,110,201,248,123,67 ],
		[ 237,114,121,205,231,88,56,34,182,190,62,123,243,252,2,236 ],
		[ 152,187,250,101,26,251,130,193,110,145,149,212,73,39,191,138 ],
		[ 8,12,29,139,151,244,30,9,11,87,218,149,152,92,22,246 ],
		[ 63,11,161,255,230,141,116,83,143,39,65,231,185,126,246,170 ],
		[ 128,245,151,12,111,204,71,170,139,246,19,222,188,68,227,186,60,117,238, 67,4,170,100,95,104,133,87,153,124,212,128,12 ],
		[ 20,77,65,9,13,109,229,60,0,3,186,56,190,90,48,93,186,122,200,16,202,13, 249,218,145,118,223,243,232,130,161,94 ],
		[ 4,57,187,192,5,81,173,237,228,166,182,157,23,47,153,229,109,161,81,4,202, 190,174,72,69,192,98,174,228,68,109,26 ],
		[ 247,71,207,142,146,27,182,0,67,12,235,174,107,70,38,165,186,169,21,187, 8,150,91,122,118,176,192,191,179,73,194,126 ],
		[ 243,51,36,207,216,59,71,0,130,237,118,32,61,223,238,214,136,65,188,52,68, 85,5,116,68,66,7,76,55,14,120,129 ],
		[ 132,15,0,170,117,62,62,232,76,31,204,103,92,224,225,162,224,244,164,189, 11,87,105,241,166,52,122,100,2,131,86,195 ],
		[ 14,90,143,161,121,159,73,147,26,248,88,201,32,241,198,177,88,147,168,10, 51,161,85,86,153,111,216,159,16,252,171,50 ],
		[ 46,137,166,99,10,9,161,19,201,26,190,248,124,221,138,23,18,119,130,83,66, 31,222,255,117,127,135,107,76,241,172,196 ],
		[ 65,96,98,247,42,85,245,104,121,123,23,102,33,130,213,150,181,251,20,191, 179,109,207,13,133,68,150,154,136,143,17,127 ],
		[ 238,77,117,246,217,33,56,85,205,216,1,163,42,189,112,85,104,65,145,65,200, 102,245,25,59,71,59,25,13,18,195,24 ],
		[ 175,155,175,187,29,60,129,58,151,108,248,196,181,96,156,242,113,215,42, 220,224,154,193,233,161,108,45,40,235,201,145,173 ],
		[ 143,58,180,175,39,226,132,151,224,46,144,191,193,230,87,90,46,125,106,225, 132,19,164,242,55,66,21,27,102,81,144,122 ],
		[ 119,60,95,2,38,129,245,99,74,20,55,199,56,162,238,64,44,89,38,8,255,225, 61,149,118,93,166,195,45,242,240,116 ],
		[ 1,140,255,176,19,225,59,182,85,220,132,29,98,57,1,59,33,163,1,83,60,3,232, 118,143,129,29,185,67,97,238,196 ],
		[ 24,236,188,144,157,4,152,167,29,125,37,66,220,168,245,72,50,191,158,70, 190,26,98,59,166,241,193,103,162,233,246,160 ],
		[ 89,121,164,54,147,181,38,167,34,213,245,92,174,126,14,74,144,110,146,95, 56,8,38,153,15,146,74,151,68,134,180,176 ],
		[ 73,13,241,83,220,5,32,25,68,34,116,111,234,221,64,94,20,55,93,242,83,11, 10,59,4,39,196,222,150,229,198,25,197,128,19,78,216,100,168,207,141,207, 175,29,120,24,159,29 ],
		[ 33,223,228,40,106,73,254,13,208,234,230,228,21,44,21,176,85,54,208,216, 187,55,175,198,63,31,60,191,244,84,76,25,115,157,106,166,73,145,102,46, 205,155,243,19,175,205,27,242 ],
		[ 2,229,11,152,59,105,209,14,144,148,195,182,137,119,145,89,143,185,212,8, 92,100,130,107,224,49,77,12,117,89,242,28,147,67,78,81,207,254,255,35,104, 132,93,28,169,163,249,17 ],
		[ 111,183,30,238,137,12,169,152,246,29,162,184,195,17,54,50,158,30,165,140, 231,255,180,250,127,237,85,80,133,88,228,246,97,52,13,120,114,104,192,7, 124,122,226,100,6,215,94,254 ],
		[ 14,133,180,190,194,136,108,116,80,17,2,6,113,129,33,134,150,121,255,152, 92,11,119,196,41,190,114,154,218,224,100,158,252,173,25,54,78,14,152,253, 29,91,51,49,138,133,86,195 ],
		[ 192,149,185,128,17,143,153,163,22,175,42,239,4,247,86,13,193,15,42,76,11, 22,17,17,110,117,125,251,35,30,218,133,190,140,152,74,106,130,88,87,68, 66,174,234,38,215,69,155 ],
		[ 179,112,80,9,233,55,89,134,49,254,119,181,114,238,13,90,158,193,50,2,158, 190,123,71,69,116,117,112,97,248,229,220,189,64,119,137,124,204,221,98, 198,109,77,186,158,215,209,17 ],
		[ 198,176,231,134,208,202,53,132,147,42,126,194,79,209,138,230,207,20,149, 59,47,229,137,27,126,46,234,18,240,100,194,183,201,199,175,190,166,133, 3,96,150,3,238,154,231,126,239,191 ],
		[ 233,227,197,48,11,194,2,96,106,121,24,213,29,135,235,72,143,178,52,214, 40,169,50,108,229,158,18,236,235,164,101,76,21,14,97,243,92,93,225,101, 7,203,68,115,114,79,86,210 ],
		[ 81,215,124,227,54,15,90,239,248,126,23,163,219,13,245,41,30,86,44,249,134, 52,221,127,240,30,141,123,249,8,126,221,226,156,188,235,158,84,165,56,158, 38,168,121,44,161,108,170 ],
		[ 215,156,195,2,145,102,237,9,196,188,163,145,199,35,228,179,28,23,23,249, 85,178,209,135,93,115,173,126,89,48,247,135,179,30,19,89,183,168,203,102, 34,125,207,137,33,84,227,20 ],
		[ 170,236,23,110,135,242,16,240,127,212,197,62,37,130,87,182,134,247,119, 78,61,134,173,159,214,68,203,93,143,247,247,101,163,234,79,216,76,234,227, 48,189,92,125,103,41,47,171,205 ],
		[ 118,70,104,186,35,9,3,77,66,135,235,65,99,242,94,169,113,10,14,103,68,106, 70,10,7,149,242,62,30,100,71,50,149,137,115,146,220,185,252,36,127,222, 232,223,134,45,200,14 ],
		[ 204,140,213,118,192,233,188,143,4,121,4,162,134,98,186,184,2,181,226,224, 108,234,26,82,94,22,96,49,161,202,40,239,201,13,29,73,250,175,210,176,50, 154,87,70,145,107,239,20 ],
		[ 160,68,57,205,169,228,3,107,118,58,91,200,14,166,79,44,219,181,213,27,86, 55,142,117,151,55,78,224,219,81,220,167,183,230,20,196,175,133,245,162, 22,86,144,66,85,214,187,235 ],
		[ 117,117,63,173,126,63,35,138,8,100,76,65,228,108,114,250,70,168,83,107, 133,12,248,18,209,232,62,247,111,94,200,8,174,49,96,108,36,74,30,114,188, 9,136,225,58,105,51,142 ],
		[ 157,1,60,58,10,176,179,199,24,164,77,239,147,96,254,187,168,93,172,8,209, 103,62,122,61,41,35,55,119,107,79,203,4,137,86,53,211,205,221,229,143,71, 131,69,42,4,155,104,19,174,125,223,242,28,65,211,195,41,197,208,9,137,2, 78 ],
		[ 161,212,83,134,155,103,237,212,88,188,177,162,36,16,53,8,52,218,66,239, 202,210,19,78,147,73,227,127,80,128,211,173,204,38,139,59,116,112,213,51, 177,127,54,250,142,13,149,250,174,240,91,131,2,217,59,89,21,210,246,95, 66,231,75,8 ],
		[ 83,56,156,44,197,77,160,143,93,249,83,46,110,207,34,249,155,249,53,121, 66,232,94,72,59,131,210,129,52,13,60,111,5,114,192,85,26,153,9,232,165, 43,102,200,94,173,217,165,181,77,236,252,53,247,89,255,9,16,240,150,230, 180,19,88 ],
		[ 6,9,131,74,104,2,18,36,129,24,75,80,246,121,209,152,247,9,20,55,148,155, 204,85,241,117,128,236,174,73,57,46,62,238,12,196,175,137,79,112,255,52, 218,205,195,135,94,141,213,213,170,144,62,45,91,199,225,185,22,145,155, 75,180,40 ],
		[ 124,27,241,23,212,79,223,87,129,214,34,161,230,240,168,245,116,197,84,67, 41,197,102,155,244,188,36,21,201,194,105,78,28,74,28,212,67,148,94,239, 182,211,130,4,133,147,2,20,91,226,222,159,41,63,206,184,198,205,148,138, 44,41,209,176 ],
		[ 84,104,143,97,29,117,50,48,5,241,116,142,186,158,229,99,95,186,245,237, 197,79,211,176,187,159,127,74,118,17,13,109,247,24,241,3,78,96,255,102, 180,70,228,123,173,59,151,163,110,9,111,199,107,146,179,188,137,61,103, 6,185,247,245,212 ],
		[ 118,110,183,199,103,39,114,241,127,81,119,239,215,127,28,236,115,64,116, 215,102,93,214,207,89,250,200,192,36,25,87,11,44,222,212,149,204,148,44, 255,188,58,157,25,127,24,153,122,92,89,37,133,216,96,141,185,45,115,99, 238,182,33,112,95 ],
		[ 196,213,190,214,69,184,227,220,28,132,237,60,124,167,236,17,174,150,24, 54,114,226,1,196,58,76,25,44,14,102,157,206,13,130,245,161,22,13,213,96, 116,154,246,227,241,139,102,219,182,152,20,131,26,167,38,159,239,236,210, 176,196,156,78,60 ],
		[ 101,147,225,111,103,140,133,149,241,30,23,60,65,248,83,131,194,253,65,198, 18,236,205,213,115,120,194,165,245,70,82,13,125,178,225,131,15,64,240,72, 16,112,128,30,154,57,15,92,25,130,55,222,255,112,188,112,253,246,189,26, 236,207,114,47 ],
		[ 199,161,228,120,85,125,46,243,141,87,89,70,88,113,253,104,68,254,5,237, 79,200,203,144,50,96,208,78,11,252,199,1,138,248,58,220,188,225,124,68, 197,210,249,31,167,107,86,202,222,124,145,187,104,231,99,155,255,235,59, 250,72,223,7,101 ],
		[ 41,194,24,135,196,138,136,5,61,201,81,96,150,96,116,201,105,26,31,123,131, 17,29,120,92,6,70,70,121,35,195,157,218,41,224,155,223,95,191,65,225,217, 172,68,235,37,46,203,73,169,206,26,45,8,20,42,248,142,0,204,80,183,202, 177 ],
		[ 99,45,35,44,153,237,60,32,122,156,158,17,225,48,53,103,117,46,94,91,200, 93,249,48,206,3,49,171,145,121,194,237,55,137,190,21,200,179,79,196,36, 24,114,252,203,99,187,180,235,139,174,154,64,206,219,5,87,11,209,203,254, 149,196,110 ],
		[ 225,41,74,127,96,108,234,255,19,129,178,139,43,244,113,146,94,129,129,151, 162,53,237,55,166,238,103,141,215,190,234,142,213,53,110,62,155,188,217, 187,39,234,214,239,115,53,194,98,211,4,95,17,17,213,8,199,12,171,162,172, 211,68,203,177 ],
		[ 133,100,189,25,253,43,51,103,6,1,99,156,196,62,72,216,144,23,214,84,223, 186,74,6,188,98,149,157,80,31,35,94,34,126,251,237,93,139,167,89,214,81, 30,116,203,109,6,84,53,239,29,119,201,20,195,143,161,81,55,14,75,20,212, 97 ],
		[ 161,27,115,145,250,123,188,180,210,181,75,188,168,100,241,180,63,59,107, 97,45,130,179,244,244,236,131,108,31,3,180,168,187,141,72,135,252,234,134, 154,82,190,151,129,147,249,243,134,184,30,87,184,75,232,141,66,207,0,133, 53,15,51,67,212 ],
		[ 101,160,120,89,138,55,143,101,149,250,239,152,122,121,84,36,214,3,120,13, 136,24,77,150 ],
		[ 203,174,244,74,38,46,117,60,68,66,72,177,59,67,128,132,145,155,75,155,158, 184,152,248,112,114 ],
		[ 174,186,45,36,166,134,195,43,166,108,76,55,245,5,165,205,26,117,120,118, 91,84,128,109,248,65,3,96 ],
		[ 166,192,210,132,109,61,0,253,174,98,153,105,16,224,193,146,94,252,231,155, 12,117,68,168,16,79,193,74,238,98 ],
		[ 204,231,166,234,4,44,45,128,31,41,88,61,211,74,103,23,115,20,240,79,191, 85,176,28,201,232,251,73,118,217,238,47 ],
		[ 14,209,202,119,79,43,96,216,89,90,223,163,37,248,28,168,129,187,100,114, 72,199,168,20,109,194,49,72,48,185,97,120,41,82 ],
		[ 228,190,242,61,252,95,94,21,207,75,6,8,131,254,215,92,34,180,100,2,59,79, 70,67,85,190,230,161,70,182,219,114,103,239,104,19 ],
		[ 166,69,162,214,21,198,15,56,236,125,233,198,240,135,76,81,80,9,126,200, 209,190,28,55,165,230,72,5,187,49,171,199,189,83,43,183,171,165 ],
		[ 177,104,86,135,228,33,176,89,104,110,111,15,240,197,48,207,123,81,89,55, 116,150,14,68,146,182,12,108,211,32,144,183 ],
		[ 3,23,173,220,246,1,189,8,243,33,118,204,157,144,69,12,155,20,149,55,254, 9,10,48,19,130,156,28,32,213,178,103,173 ],
		[ 44,194,119,220,37,79,65,47,132,215,159,182,87,94,165,188,26,73,227,116, 226,189,48,4,226,71,125,220,25,11,181,221,232,32 ],
		[ 154,166,121,23,155,28,43,106,215,235,89,109,245,7,235,90,161,140,15,100, 64,2,35,58,45,49,203,157,132,42,19,86,11,180,248 ],
		[ 190,26,115,144,206,183,93,13,47,174,150,237,36,71,248,202,42,23,154,31, 212,8,111,199,18,75,138,153,168,207,225,232,212,197,242,234 ],
		[ 7,183,194,218,57,173,45,230,80,11,30,194,44,209,179,93,113,191,126,147, 117,174,4,4,174,98,246,59,74,120,233,65,176,39,0,220,234 ],
		[ 204,109,168,196,153,13,43,138,85,164,29,155,94,196,219,10,1,0,204,253,87, 227,228,104,77,42,45,139,116,82,100,110,250,30,225,12,157,244 ],
		[ 158,101,171,59,253,115,222,45,156,1,116,105,156,8,247,63,131,52,177,40, 52,245,6,115,127,73,142,76,223,215,11,151,73,84,164,13,205,213,51 ]
		];
}
