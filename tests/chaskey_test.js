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
			key			: '#key',	
			nonce		: '#nonce',	
			message		: '#message',	
			ciphertext	: '#ciphertext',
			encrypt		: '#encrypt', 
			decrypt		: '#decrypt', 
			sign		: '#sign', 
			format		: '#format'	
		};
		var ui = this.ui;
		Object.keys(ui).every(function(id) {
			ui[id] = document.querySelector(ui[id]);
			return true;
		});
		var backend = this;
		backend.ui = ui;
		
		this.ui.encrypt.onclick = function() {
			backend.encrypt();
		}
		this.ui.decrypt.onclick = function() {
			backend.decrypt();
		}
		this.ui.sign.onclick = function() {
			backend.sign();
		}
		this.ui.format.onchange = function() {
			backend.formatchange();
		}
		this.ui.ciphertext.onchange = function() {
			this.format = null;
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
		this.ui.key.value = bytes2hex(key,',').toUpperCase();
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
		if( key.length != 16 && key.length != 4) {
			throw new Error('Invalid key length:' + key.length);
		}
		if( key.length == 16)
			key = key.map(function(v) { return validByte(parseInt(v, 16), v);	});
		else
			key = key.map(function(v) { return validInt(parseInt(v, 16), v);	});
		return new Uint32Array(Uint8Array.from(key).buffer);
	}

	
	this.encrypt = function() {
		try{
			var cbc = new ChaskeyCipher.Cbc();
			cbc.set(this.readKey());
			cbc.init(this.ui.nonce.value);
			var cif = cbc.encrypt(this.encoder.encode(this.ui.message.value));
			
			if( this.ui.format.value === 'base-64' )
				this.ui.ciphertext.value = btoa(String.fromCharCode.apply(null, cif));
			else
				this.ui.ciphertext.value = bytes2hex(cif);

			this.ui.ciphertext.format = this.ui.format.value; 

		} catch(e) {
			this.error('ERROR:',e.message)
		}
	}

	this.decrypt = function() {
		try{
			var cbc = new ChaskeyCipher.Cbc();
			cbc.set(this.readKey());
			cbc.init(this.ui.nonce.value);
			
			var format = this.ui.ciphertext.format || this.ui.format.value;
			var cif;
			
			if( format === 'base-64' )
				cif = Uint8Array.from(atob(this.ui.ciphertext.value).split('').map(function (c) { return c.charCodeAt(0); }));
			else
				cif = bytes2string(this.ui.ciphertext.value);
			
			this.ui.message.value =  this.decoder.decode(cbc.decrypt(cif)).split(this.zero)[0];
		} catch(e) {
			this.error('ERROR:',e.message)
		}
		
	}

	this.sign = function() {
		try {
			var mac = new ChaskeyCipher.Mac();
			mac.set(this.readKey());			
			var cif = mac.sign(this.encoder.encode(this.ui.message.value));
			
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
				this.error("error: test_CBC/encrypt:",this.plaintext.substr(0,i));
				this.debug("got                    : ", bytes2hex(cif));
				this.debug("expected               : ", bytes2hex(this.masters[i-1]));
				res = false;
			}
			cbc.initIV([0,0,0,0]);
			var txt = cbc.decrypt(cif);
			if( ! compare(txt, msg, i) ) {
				this.error("error: test_CBC/decrypt:",  this.plaintext.substr(0,i));
				this.debug("got                    : ", bytes2hex(txt));
				this.debug("expected               : ", bytes2hex(msg));
				res = false;
			}
		}
		return res;
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
		[ 165,250,237,216,206,149,124,139,208,234,246,224,253,53,175,148 ],
		[ 84,105,113,180,23,1,6,3,243,123,6,70,242,249,54,171 ],
		[ 209,56,102,101,234,74,253,215,74,207,244,132,181,236,205,167 ],
		[ 31,171,191,56,175,91,156,215,254,159,85,68,53,60,132,131 ],
		[ 148,184,91,22,229,223,194,83,233,61,83,100,105,212,222,119 ],
		[ 39,201,32,249,182,103,155,165,96,10,61,144,161,178,24,162 ],
		[ 132,227,77,193,163,253,205,144,169,4,159,99,74,131,60,122 ],
		[ 95,178,5,34,170,144,36,202,46,57,47,9,194,37,83,2 ],
		[ 161,249,93,155,250,157,50,27,146,31,255,57,72,196,123,112 ],
		[ 133,98,195,172,193,223,248,3,85,233,144,14,215,122,73,91 ],
		[ 178,105,112,206,102,29,253,235,73,130,55,143,100,162,154,86 ],
		[ 149,224,221,214,82,130,81,221,155,110,20,43,207,26,242,132 ],
		[ 222,29,48,228,191,141,90,142,179,104,132,155,53,196,167,41 ],
		[ 15,63,156,218,187,236,208,230,186,235,84,148,137,80,103,164 ],
		[ 172,65,164,218,127,185,210,230,225,69,254,140,69,44,215,77 ],
		[ 150,23,134,134,151,145,30,133,193,96,139,102,20,98,117,227 ],
		[ 232,92,26,8,249,28,98,228,28,14,127,243,118,29,218,6,99,110,187,168,116, 241,128,108,8,211,183,138,225,225,65,193 ],
		[ 148,158,4,5,155,244,53,19,59,44,78,9,1,138,79,210,89,77,155,131,172,157, 148,238,78,243,41,24,165,83,208,133 ],
		[ 118,13,174,24,27,42,110,253,249,112,11,115,249,158,164,155,250,168,48,92, 58,255,87,160,58,196,224,147,211,224,112,86 ],
		[ 180,226,131,116,140,204,195,13,143,236,138,1,46,74,67,168,123,135,186,76, 28,208,25,177,44,146,65,155,99,190,47,169 ],
		[ 57,40,175,79,56,118,68,126,253,180,253,76,24,120,66,233,15,197,201,135, 22,157,131,18,166,70,75,66,252,105,13,63 ],
		[ 197,171,175,109,152,209,154,125,2,121,101,174,109,116,209,0,116,89,166, 11,233,2,194,98,157,109,113,73,182,228,242,73 ],
		[ 79,92,175,151,51,128,197,188,196,93,174,238,217,216,91,247,58,232,156,203, 130,81,52,184,103,83,145,172,1,114,27,77 ],
		[ 27,151,28,84,104,19,228,80,88,79,56,30,146,165,37,14,76,217,110,191,118, 220,7,180,19,248,221,70,157,74,230,29 ],
		[ 214,150,214,113,101,163,81,251,255,171,220,173,9,57,163,34,193,166,4,24, 22,218,121,96,133,34,0,89,158,162,70,75 ],
		[ 20,103,8,72,62,28,105,249,250,75,88,95,16,131,208,11,12,19,12,34,11,95, 52,49,57,99,151,101,249,180,60,191 ],
		[ 251,228,194,126,69,86,169,4,181,54,159,189,44,21,0,251,193,218,161,87,198, 44,164,156,12,87,107,67,198,67,151,195 ],
		[ 98,50,187,146,249,221,170,100,108,52,26,4,5,24,244,153,254,148,204,181, 195,227,193,132,54,150,213,164,182,3,80,239 ],
		[ 143,77,158,44,47,2,156,80,56,197,216,191,180,27,138,151,102,26,104,0,15, 76,105,131,204,168,84,24,12,104,179,171 ],
		[ 173,98,19,236,95,233,79,23,85,120,71,136,66,219,191,163,2,178,45,71,63, 226,41,111,100,137,247,208,24,82,87,203 ],
		[ 53,224,97,43,68,248,46,93,19,117,233,158,195,28,241,215,25,91,119,26,199, 57,38,249,103,16,117,135,207,201,241,9 ],
		[ 246,142,23,86,91,82,200,144,186,40,153,223,206,222,34,50,82,28,166,183, 52,198,253,218,14,57,103,26,92,197,23,131 ],
		[ 122,231,181,140,68,198,146,169,43,236,247,106,212,95,45,218,58,51,210,230, 63,202,174,224,107,164,165,44,53,241,235,16,78,31,44,9,19,180,197,250,183, 21,155,203,223,22,149,194 ],
		[ 84,206,7,239,39,170,74,96,113,230,48,62,117,150,79,89,238,81,209,224,75, 13,66,5,211,212,163,67,117,12,197,222,164,166,201,246,87,186,236,112,227, 66,201,173,85,132,141,54 ],
		[ 58,140,215,120,216,206,113,138,37,1,53,1,130,118,251,237,131,2,191,185, 110,231,251,215,173,242,117,23,65,115,72,57,111,234,232,178,186,50,72,135, 218,124,223,63,171,244,232,228 ],
		[ 9,219,245,242,253,254,156,173,209,161,63,59,95,72,130,178,36,173,236,126, 97,195,98,170,235,107,106,111,121,220,124,125,181,33,18,68,149,238,103, 25,254,41,172,129,8,146,170,69 ],
		[ 250,131,21,5,190,225,247,160,137,164,86,178,250,100,72,173,52,202,209,147, 145,250,151,135,178,195,35,200,7,41,186,179,179,254,26,165,43,240,245,100, 127,30,173,48,177,104,22,164 ],
		[ 249,31,108,218,85,167,76,124,112,156,189,219,216,138,16,130,234,248,57, 205,187,103,192,215,211,39,178,222,180,105,60,18,192,163,93,150,2,220,40, 255,151,234,161,63,245,157,44,238 ],
		[ 172,11,246,110,90,219,44,179,172,79,6,169,89,39,136,242,1,129,104,54,141, 190,176,128,172,184,191,154,31,123,145,245,42,38,192,132,54,117,108,64, 35,89,221,127,13,168,84,40 ],
		[ 225,124,76,83,37,37,33,21,157,30,234,98,4,230,221,66,76,104,198,26,79,70, 206,66,242,151,122,30,188,110,142,222,90,125,97,96,184,88,192,129,67,199, 116,46,21,68,167,26 ],
		[ 160,60,156,133,196,112,203,190,65,135,143,218,202,211,75,23,189,225,232, 13,49,44,1,152,182,131,145,193,182,78,24,196,88,125,48,34,58,22,23,78,171, 67,74,38,57,97,55,86 ],
		[ 120,165,182,201,65,20,165,118,24,24,122,182,93,89,80,222,250,224,208,221, 141,132,170,151,7,152,169,66,199,126,138,73,223,181,29,199,72,178,25,72, 28,189,84,32,63,150,4,39 ],
		[ 42,10,154,84,126,234,117,134,38,144,127,182,65,194,110,156,145,107,18,241, 145,37,219,167,144,198,146,44,35,43,20,36,93,226,34,237,14,32,139,193,36, 51,80,8,153,39,246,181 ],
		[ 237,219,80,208,252,112,128,213,230,247,64,226,60,231,179,155,13,66,249, 25,207,146,220,207,53,85,129,7,55,32,120,95,209,132,67,66,100,6,85,157, 255,94,217,245,177,83,167,226 ],
		[ 11,237,8,66,171,133,247,77,113,60,84,75,91,234,180,56,4,25,67,72,148,192, 197,78,168,39,253,177,194,82,212,128,33,140,95,62,102,82,129,96,52,201, 52,191,111,158,149,169 ],
		[ 45,75,192,168,56,6,44,146,45,120,195,9,50,146,8,97,22,119,131,153,90,59, 155,41,188,39,240,239,195,164,103,134,195,76,22,247,96,124,177,146,87,188, 34,43,221,76,4,54 ],
		[ 99,230,201,126,14,221,86,28,183,1,241,164,112,90,233,249,250,212,141,28, 165,242,247,103,8,101,190,195,12,7,41,183,167,78,39,211,5,164,2,148,40, 29,82,64,80,154,3,29 ],
		[ 84,27,67,191,39,155,36,230,128,119,201,236,191,211,154,216,172,196,148, 234,202,4,141,5,142,242,97,154,175,143,43,119,117,181,176,254,227,74,36, 225,213,216,79,151,9,69,148,32 ],
		[ 175,240,207,50,233,55,6,144,29,113,55,231,180,108,249,65,9,241,25,9,198, 238,243,71,38,183,105,210,164,36,177,181,91,245,182,165,225,29,114,126, 180,91,111,167,69,181,19,238,123,121,220,12,23,178,19,231,186,109,198,228, 201,73,240,18 ],
		[ 133,60,117,46,241,121,104,235,46,158,174,63,19,189,87,113,154,243,222,104, 144,4,251,138,245,211,143,62,221,40,232,52,13,45,69,65,7,98,95,80,118,173, 202,13,61,232,204,135,33,201,26,83,60,249,124,118,195,70,31,232,54,171, 84,191 ],
		[ 105,153,58,56,56,47,57,201,37,75,30,191,172,65,188,195,156,200,68,44,132, 187,143,228,166,195,233,224,179,22,56,182,188,239,94,43,214,99,72,112,34, 140,14,111,3,18,160,35,128,77,217,81,90,144,216,100,247,211,253,59,53,119, 197,235 ],
		[ 241,212,163,180,65,80,66,34,21,235,130,169,123,208,176,219,187,135,9,191, 89,114,123,187,5,94,130,226,255,30,103,157,46,50,205,147,45,60,223,1,83, 49,165,172,176,36,209,125,71,107,62,44,99,46,47,90,25,32,101,253,152,116, 166,130 ],
		[ 64,184,22,10,66,83,39,96,63,177,155,120,28,84,167,53,128,182,153,243,177, 52,117,238,170,215,53,174,178,47,128,57,130,167,81,97,30,97,225,218,171, 88,226,239,50,33,224,63,3,12,241,111,196,78,236,197,48,67,28,182,237,167, 83,91 ],
		[ 206,118,95,62,112,61,28,175,12,165,84,29,120,226,168,226,205,58,110,124, 102,27,119,116,189,33,182,167,99,16,235,181,11,227,61,104,114,134,225,134, 204,56,228,236,88,131,162,154,160,237,235,84,80,220,185,145,145,30,83,176, 77,120,16,147 ],
		[ 211,50,200,38,183,154,166,198,74,210,55,240,212,201,170,175,248,99,209, 43,122,8,74,39,101,169,64,38,86,176,43,138,161,215,225,237,175,166,251, 31,251,44,97,44,18,137,189,6,134,60,153,28,136,46,114,90,110,144,14,89, 126,204,8,180 ],
		[ 106,59,194,87,133,38,143,165,203,90,94,39,71,129,43,171,165,158,223,30, 232,18,211,250,149,212,154,187,83,126,212,6,92,97,190,139,255,5,219,29, 76,64,71,16,202,42,34,163,247,147,70,64,80,30,247,206,16,242,229,186,46, 1,186,167 ],
		[ 6,237,99,216,199,114,13,156,96,163,23,4,65,147,212,76,192,106,152,200,193, 112,167,51,37,182,61,234,33,178,128,1,168,114,204,91,240,38,197,204,153, 77,249,1,100,40,47,254,132,65,176,174,108,81,22,86,160,249,185,37,65,8, 236,136 ],
		[ 140,44,192,136,157,192,137,95,126,103,199,53,154,24,57,136,166,241,241, 147,14,79,164,202,211,176,232,18,1,5,253,117,78,24,240,129,99,181,126,149, 102,4,250,103,161,10,12,35,183,148,148,80,74,179,18,106,149,155,81,13,151, 182,77,48 ],
		[ 159,252,46,224,131,106,96,255,216,1,144,144,209,173,248,75,130,172,235, 0,107,21,176,25,20,91,107,195,123,211,18,72,149,67,52,13,178,42,14,52,240, 223,114,250,211,144,38,109,3,14,40,14,107,40,27,122,91,206,152,10,208,136, 6,66 ],
		[ 118,48,158,17,226,192,53,37,153,90,241,48,26,80,93,35,44,255,215,10,5,15, 252,63,162,187,154,19,171,227,3,52,188,25,243,90,169,209,230,158,185,86, 188,216,126,246,49,127,253,129,138,49,242,45,219,104,9,11,174,133,214,129, 212,95 ],
		[ 227,184,185,148,104,123,166,112,37,174,47,218,28,160,13,84,180,208,62,179, 61,121,201,79,183,13,197,23,52,141,165,65,6,0,162,182,59,183,17,158,249, 81,249,134,139,186,18,57,252,229,127,35,9,210,94,194,48,245,45,111,60,77, 41,254 ],
		[ 209,176,29,144,127,137,50,245,86,31,120,118,24,128,57,207,194,0,113,204, 185,83,70,247,131,159,60,44,121,0,197,177,36,123,156,203,241,247,165,24, 15,103,239,43,100,145,131,177,61,162,132,88,14,155,104,252,139,186,85,229, 208,185,84,251 ],
		[ 118,225,52,1,118,22,175,60,185,157,195,24,132,81,24,203,236,137,40,85,166, 88,140,105,195,74,81,29,92,74,142,221,151,34,158,85,230,233,31,90,139,119, 96,49,109,85,51,154,107,162,228,119,88,65,80,217,22,140,232,86,26,54,15, 206 ],
	];
}

/** patching IE 																*/ 
if( ! Array.from ) {
	Array.from = function(src) {
		var dst = new Array(src.length);
		dst.every(function(v,i) { dst[i] = src[i]; return true; });
		return dst;
	}
}
