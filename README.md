# Chaskey cipher

Chaskey is a lightweight 128-bit encryption algorithm
(please follow this link for details http://mouha.be/chaskey/)<br>
This project provides C++ and JavaScript implementations of Chaskey algorithm with two modes of operations: CBC and MAC.<br>
Design of both C++ and JavaScript versions follows high-granular decomposition on the following abstractions:

* Block – a block of bits stored as an array of integers (32x4)
* Formatter – formats input string of bits as blocks, either buffering them or with zero-copy direct access
* Cipher – implements forward and reverse transformations of the underlying block
* Cbc – Cipher Block Chaining mode of operation 
* Mac – Message Authentication mode of operation 

In C++ primitives are implemented as templates, so that a cipher instance ultimately appears as  `Cbc<Cipher<N>,Formatter>` or `Mac<Cipher<N>,Formatter>`, where N is a number of transformation rounds, set equal to 8 in Chaskey8 class.<br>
In JavaScript same primitives are  implemented as objects . Online demo is available on http://hutorny.in.ua/chaskey/

## Usage

### C++

```c++
#inlcude <chaskey.hpp>


// MAC
crypto::chaskey::Cipher8::Mac mac;	// instantiate a cipher in MAC mode 
mac.set(key);						// set the key
mac.init();							// init  cipher if instance is reused
mac.update(message,length,false);	// make as many calls as needed with any message length 
mac.update(message,length,true);	// make one final call 
mac.write(ouput);					// write signature to the output or 	
mac.verify(tag);					// verify against a signature

// CBC
crypto::chaskey::Cipher8::Cbc cbc;	// instantiate a cipher in CBC mode
cbc.set(key);						// set the key
cbc.init(nonce, strlen(nonce));		// init  cipher with a nonce 
while(in) {							
	char msg[chunk_size];			 
	size_t len = in.read(msg,sizeof(msg)).gcount(); 		// read input by chunks
	cbc.encrypt(out, (const uint8_t*)msg, len, in.eof());	// and encrypt or
	//cbc.encrypt(out, (const uint8_t*)msg, len, in.eof());	// decrypt data
}
``` 

 
### JavaScript
```javascript
// MAC
var mac = new ChaskeyCipher.Mac();	// instantiate a cipher in MAC mode
mac.set(key);						// set the key
var cif = mac.sign(message);		// sign the message

// CBC
var cbc = new ChaskeyCipher.Cbc();	// instantiate a cipher in CBC mode
cbc.set(key);						// set the key
cbc.init(nonce);					// init  cipher with a nonce
var cif = cbc.encrypt(message);		// encrypt the message
```
## Perfromace 

Table below lists benchmarking results for 1M operations on a 32-bytes-long message.

|    Mach    | F, MHz|  Core    |   Arh     | Ref.MAC | Cpp MAC |  MAC    | Encrypt | Decrypt |
|------------|------:|:--------:|-----------|--------:|--------:|--------:|--------:|--------:|
|i586        | 3,400 |   i586   | x86_32    |      57 |      57 |      52 |      47 |      53 |
|Linkit Smart|   580 | MT7688   | MIPS 32 le|     990 |     890 |     930 |     860 |     960 |
|Carambola2  |   400 | AR9331   | MIPS 32 be|-- N/A --|   1,730 |    1750 |   2,670 |   2,820 |
|Photon      |   120 | STM32F   | ARM 32    |   3,176 |   2,441 |   2,455 |   2,154 |   3,051 |
|Teensy3     |    72 | MK20DX   | ARM 32    |   6,513 |   5,053 |   4,886 |   4,384 |   6,849 |
|NodeMCU<sup>*</sup>|80| LX106  | RISC 32   |-- N/A --|   8,490 |   9,310 |  11,590 |  10,930 |
|MSP430      |     8 | MSP430   | CISC 16   |-- N/A --| 431,000 | 398,000 | 388,000 | 577,000 |
|Arduino Mega|     8 |ATmega2560| AVR 8     | 763,000 | 744,000 | 746,000 | 740,000 | 822,000 |

Values are give in ms, All binaries were compiled with gcc option -O3 -- Optimize most.<br> 
<sup>*</sup>NodeMCU values are extrapolated from tests with 100K operations

Next table shows same results in normilized form - clock cycles per one operation

|    Mach    | F, MHz|  Core    |   Arh     | Ref.MAC | Cpp MAC |   MAC   | Encrypt | Decrypt |
|------------|------:|:--------:|-----------|--------:|--------:|--------:|--------:|--------:|
|i586        | 3,400 |   i586   | x86_32    |   194   |   194   |   177   |    160  |   180   |
|Linkit Smart|   580 | MT7688   | MIPS 32 le|   574   |   516   |   539   |    499  |   557   |
|Carambola2  |   400 | AR9331   | MIPS 32 be|-- N/A --|   692   |   700   |   1068  |  1128   |
|Photon      |   120 | STM32F   | ARM 32    |   381   |   293   |   295   |    258  |   366   |
|Teensy3     |    72 | MK20DX   | ARM 32    |   469   |   364   |   352   |    316  |   493   |
|NodeMCU     |    80 | LX106    | RISC 32   |-- N/A --|   679   |   745   |    927  |   874   |
|MSP430      |     8 | MSP430   | CISC 16   |-- N/A --|  3448   |  3184   |   3104  |  4616   |
|Arduino Mega|     8 |ATmega2560| AVR 8     |  6104   |  5952   |  5968   |   5920  |  6576   |
