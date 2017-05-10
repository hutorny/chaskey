/*
 * Copyright (C) 2015 Eugene Hutorny <eugene@hutorny.in.ua>
 *
 * teensy.cpp - cojson tests, Teensy 3.1 specific implementation
 *
 * This file is part of COJSON Library. http://hutorny.in.ua/projects/cojson
 *
 * The COJSON Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License v2
 * as published by the Free Software Foundation;
 *
 * The COJSON Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the COJSON Library; if not, see
 * <http://www.gnu.org/licenses/gpl-2.0.html>.
 */
#include <configuration.h>
#include <stdarg.h>
#include <string.h>
#include "esp8266_user.h"

static struct Console {
	inline void write(const char* s) noexcept { serial_write(s); }
	inline void write(char c) noexcept { serial_writec(c); }
	inline bool available() noexcept { return serial_available(); }
	char read() noexcept { return serial_read(); }
	inline Console() {
	}
	static inline void attach() {
		user_rx_installcb(rx_callback);
		user_hb_installcb(hb_callback);
	}
private:
	bool command(unsigned len);
	static void rx_callback(unsigned len);
	static void hb_callback(int cnt) {
		if( ! busy ) {
			serial_write(cnt & 1 ? "\r:" : "\r.");
		}
	}
	static bool busy;
} Serial;

void Console::rx_callback(unsigned len) {
	busy = true;
	busy = Serial.command(len);
}

void console_attach() {
	Console::attach();
}

bool Console::busy = false;
extern bool test();
extern bool bench(unsigned long);

bool Console::command(unsigned len) {
	static unsigned long  value = 0;
	int chr;
	while(len--) {
		chr = read();
		switch( chr ) {
		default: write("\r?"); break;
		case '\r':
		case '\n':
			if( value ) {
				system_soft_wdt_stop();
				bench(value);
				system_soft_wdt_restart();
			}
			else test();
			value = 0;
			return false;
		case '\t':
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
	return true;
}

unsigned long milliseconds() {
	return system_get_time() / 1000;
}


extern "C" void ets_printf(const char*, ...);

void LogAppender::log(miculog::level lvl, const char* fmt, ...) noexcept {
	using typename miculog::level;
	switch( lvl ) {
	case level::fail:
		ets_printf("FAILED\t:");
		break;
	case level::error:
		ets_printf("error\t:");
		break;
	default:;
	}
	va_list args;
	va_start(args, fmt);
	ets_vprintf(ets_putc, fmt, args);
	va_end(args);
}
