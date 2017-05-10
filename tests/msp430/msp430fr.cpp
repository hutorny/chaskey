/*
 * Copyright (C) 2017 Eugene Hutorny <eugene@hutorny.in.ua>
 *
 * msp430fr.cpp - chaskey tests, MSP430 specific implementation (not finished)
 */

#include <configuration.h>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include "miculog.hpp"
#include <msp430.h>
#include "msp430fr5xx_6xxgeneric.h"

#include "msp430.hpp"


using namespace msp430;
constexpr uart tty(msp430::uart::channel_t::esci_a0);
constexpr uart aux(msp430::uart::channel_t::esci_a1);
using led_red = gpio::port<gpio::port_t::p1>::pin<0>;
using led_grn = gpio::port<gpio::port_t::p9>::pin<7>;

extern miculog::Log<TestLog> log;


inline bool tty_get(char& c) noexcept {
	return tty.get(c, aux.blocking_t::blocking);
}
inline bool tty_peek(char& c) noexcept  {
	return tty.get(c, aux.blocking_t::non_blocking);
}

static inline unsigned now() noexcept { return TA2R; }


static inline volatile
bool elapsed(unsigned period, unsigned& since) noexcept {
	if(period + since < now()) return false;
	since = now();
	return true;
}

static unsigned last = 0;

static unsigned long command() {
	unsigned long value = 0;
	unsigned short chr_cnt = 0;
	char chr;
	tty.put("Enter count for benchmark or hit enter for self-test\n");
	while( ! tty_peek(chr) ) {
		if( elapsed(1000,last) ) {
			last = now();
			led_red::tgl();
			tty.put(++chr_cnt & 1 ? "\r:" : "\r.");
		}
	}

	while(true) {
		led_grn::set();
		tty.put(chr);
		switch( chr ) {
		default:
			tty.put("\r?");
			value = 0;
			break;
		case ' ':
		case '\r':
		case '\n':
			led_grn::clr();
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
		while( ! tty_peek(chr) ) {
			if( elapsed(1000, last) )
				led_grn::tgl();
		}
	}
}

static inline void init_gpio() {
    gpio::port<gpio::port_t::p1>::init();
    gpio::port<gpio::port_t::p2>::init();
    gpio::port<gpio::port_t::p3>::init();
    gpio::port<gpio::port_t::p4>::init();
    gpio::port<gpio::port_t::p5>::init();
    gpio::port<gpio::port_t::p6>::init();
    gpio::port<gpio::port_t::p7>::init();
    gpio::port<gpio::port_t::p8>::init();
    gpio::port<gpio::port_t::p9>::init();
    /* set function for LED pins */
    led_red::sel();
    led_grn::sel();
    /* Bit 4 Reserved Reserved. Must be written as 1. */
    SFRRPCR = 0x10 |
    		SYSRSTRE | SYSRSTUP; /* no NMI, pullup */

}
static inline void init_clock() {
    // Set DCO frequency to default 8MHz
	clocks::dco::setup(clocks::dco::frequency_t::_8MHz);
    // Configure MCLK and SMCLK to default 8MHz
	clocks::mclk::init<clocks::dco>(clocks::divider_t::_1);
	clocks::smclk::init<clocks::dco>(clocks::divider_t::_1);
	clocks::aclk::init<clocks::vlo>(clocks::divider_t::_1);

	/* TA2 clocked from ACLK which is clocked from VLO (10 KHz)
	 * TASSEL = 01
	 * ID = 2
	 * IDEX = 4
	 * Timer Mode = 01 Continuous
	 * After programming ID or TAIDEX bits, set the TACLR
	 *
	 * If two timers connected use 16.2.4.1.1 Capture Initiated by Software
	 *
	 * */
	TA2CTL = 0x100 | ID_1 | MC_2;
	TA2EX0 = TAIDEX_4;
	TA2CTL |= TACLR;
}

void setup() {
    WDTCTL = WDTPW | WDTHOLD | WDTCNTCL | WDTSSEL__VLO;	// Stop watchdog timer
	init_gpio();
	pmm::unlockLPM5();
    init_clock();
    tty.begin(tty.baudrate_t::_115200);
    aux.begin(aux.baudrate_t::_115200);
    tty.put("\nChaskey tests starting\n");
    aux.put("\nChaskey tests starting\n");
    aux.put("Primary output is set to another UART\n");
}

extern bool test();
extern bool bench(unsigned long);



void loop() {
	unsigned long cmd = command();
	if( cmd == 0 ) {
		log.warn("Starting self-test\n");
		test();
	}
	else {
		log.warn("Starting benchmark for %lu\n", cmd);
		bench(cmd);
	}
}

void LogAppender::log(miculog::level lvl, const char* fmt, ...) noexcept {
	using typename miculog::level;
	char buff[128] = {};
	if( lvl == level::fail )
		tty.put("FAILED\t:");
	if( lvl == level::error )
		tty.put("error\t:");
	va_list args;
	va_start(args, fmt);
	vsprintf(buff, fmt, args); /* use of vsprintf blows up binary size out of small constraints */
	tty.put(buff);
	va_end(args);
}

volatile unsigned long milliseconds() {
	return TA2R;
}

int main(void) {
	setup();
	while(true) loop();
	return 0;
}

