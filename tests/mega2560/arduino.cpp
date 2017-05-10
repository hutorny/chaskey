/*
 * main_wiring.cpp
 *
 * Test environment for wiring based platforms, such as Arduino, Photon, Teensy
 */
#include <configuration.h>
#include <Arduino.h>

void setup() {
  Serial.begin(115200);
  Serial.println("Chaskey tests starting");
  pinMode(LED_BUILTIN, OUTPUT);
}

unsigned long last = 0;
uint8_t toggle = 0;


extern bool test();
extern bool bench(unsigned long);
static unsigned long command();

unsigned long milliseconds() {
	return millis();
}

void loop() {
	unsigned long cmd = command();
	if( cmd == 0 ) test();
	else if( cmd > 0 ) bench(cmd);
}

static unsigned long command() {
	unsigned long value = 0;
	unsigned char toggle = 0;
	int chr;
	Serial.println("Enter count for benchmark or hit enter for self-test");
	while( ! Serial.available() ) {
		delay(100);
		Serial.write((++toggle) & 4 ?  "\r:" : "\r.");
		digitalWrite(LED_BUILTIN, toggle & 0x10 ? HIGH : LOW);
	}
	while(true) {
		while( ! Serial.available() ) {
			delay(100);
			digitalWrite(LED_BUILTIN, (++toggle) & 0x10 ? HIGH : LOW);
		}
		chr = Serial.read();
		Serial.write(chr);
		switch( chr ) {
		default:
			Serial.write("\r?");
			value = 0;
			break;
		case ' ':
		case '\r':
		case '\n':
			return value;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9': value = value * 10 + chr - '0'; break;
		}
	}
}

void LogAppender::log(miculog::level lvl, const char* fmt, ...) noexcept {
	using typename miculog::level;
	char buff[128] = {};
	if( lvl == level::fail )
		Serial.print("FAILED\t:");
	if( lvl == level::error )
		Serial.print("error\t:");
	va_list args;
	va_start(args, fmt);
	vsprintf(buff, fmt, args);
	va_end(args);
	Serial.write(buff);
}

