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
* Cloc – Confidentiality and Authentication mode of operation, see https://eprint.iacr.org/2014/157.pdf

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

crypto::chaskey::Cipher8::Cloc cloc;	// instantiate a cipher in CLOC mode
cloc.set(key);							// set the key
cloc.init(); 							// inity before  reusing instance
cloc.update(ad, length, false);			// feed AD by chunks
cloc.update(ad, length, true); 			// feed last AD chunk
cloc.nonce(nonce, length);				// apply noce
cloc.encrypt(out, datachunk, false);	// feed data by chunks
cloc.encrypt(out, lastdatachunk, true);	// feed last data chunk
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

|    Mach    | F, MHz|  Core    |   Arh     | Ref.MAC | ChaCha8 | Cpp MAC |  MAC    | Encrypt | Decrypt |aes128cloc|  CLOC  | 
|------------|------:|:--------:|-----------|--------:|--------:|--------:|--------:|--------:|--------:|--------:|--------:| 
|i586        | 3,400 |   i586   | x86_32    |      59 |     137 |      59 |      57 |      55 |      67 |     863 |     155 | 
|Linkit Smart|   580 | MT7688   | MIPS 32 le|   1,020 |   1,710 |     890 |     930 |     880 |     960 |  13,600 |   3,040 | 
|Carambola2  |   400 | AR9331   | MIPS 32 be|-- N/A --|   2,500 |   1,730 |    1750 |   2,700 |   2,850 |  19,740 |   7,500 | 
|Photon      |   120 | STM32F   | ARM  32   |   3,176 |   8,780 |   2,451 |   2,395 |   2,184 |   2,941 |-- N/A --|   7,507 | 
|Teensy3     |    72 | MK20DX   | ARM  32   |   6,390 |  12,926 |   5,220 |   5,346 |   5,054 |   6,055 | 193,700 |  15,450 | 
|NodeMCU<sup>*</sup>|80| LX106  | RISC 32   |-- N/A --|  12,500 |   8,570 |   7,670 |  12,200 |  12,000 |-- N/A --|  31,300 | 
|MSP430<sup>*</sup>| 8 | MSP430 | CISC 16   |-- N/A --|-- N/A --| 431,000 | 398,000 | 388,000 | 577,000 |-- N/A --|-- N/A --| 
|Arduino Mega<sup>*</sup>|8 |ATmega2560|AVR 8|764,000 | 270,000 | 900,000 | 752,000 | 738,000 | 827,000 |-- N/A --|2,610,000| 

Values are give in ms, All binaries were compiled with gcc option `-O3` -- Optimize most.<br> 
<sup>*</sup>NodeMCU, MSP430 and Arduino Mega results are extrapolated from tests with 100K operations

Next table shows same results in normilized form - clock cycles per one operation

|    Mach    | F, MHz|  Core    |   Arh     | Ref. MAC| ChaCha8 | Cpp MAC |  MAC    | Encrypt | Decrypt |aes128cloc|  CLOC  |
|------------|------:|:--------:|-----------|--------:|--------:|--------:|--------:|--------:|--------:|--------:|--------:|
|i586        | 3,400 |   i586   | x86_32    |   201   |   466   |   201   |   194   |   187   |   228   |  2934   |   527   |
|Linkit Smart|   580 | MT7688   | MIPS 32 le|   592   |   992   |   516   |   539   |   510   |   557   |  7888   |  1763   |
|Carambola2  |   400 | AR9331   | MIPS 32 be|-- N/A --|  1000   |   692   |   700   |  1080   |  1140   |  7896   |  3000   |
|Photon      |   120 | STM32F   | ARM 32    |   381   |  1054   |   294   |   287   |   262   |   353   |-- N/A --|   901   |
|Teensy3     |    72 | MK20DX   | ARM 32    |   460   |   931   |   376   |   385   |   364   |   436   | 13946   |  1112   |
|NodeMCU     |    80 | LX106    | RISC 32   |-- N/A --|  1000   |   686   |   614   |   976   |   960   |-- N/A --|  2504   |
|MSP430      |     8 | MSP430   | CISC 16   |-- N/A --|-- N/A --|  3448   |  3184   |  3104   |  4616   |-- N/A --|-- N/A --|
|Arduino Mega|     8 |ATmega2560| AVR 8     |  6112   |  2160   |  7200   |  6016   |  5904   |  6616   |-- N/A --| 20880   |


State size, including the key, dervied keys and formatter's buffer, bytes:

|    Mach    |   Arh     |   MAC   |   CBC   |  CLOC   |
|------------|-----------|--------:|--------:|--------:|
|i586        | x86_32    |    92   |     60  |    80   |
|Linkit Smart| MIPS 32 le|    92   |     60  |    80   |
|Carambola2  | MIPS 32 be|    84   |     52  |    72   |
|Photon      | ARM 32    |    92   |     60  |    80   |
|Teensy3     | ARM 32    |    92   |     60  |    80   |
|NodeMCU     | RISC 32   |    84   |     52  |    72   |
|Arduino Mega| AVR 8     |    84   |     52  |    72   |
