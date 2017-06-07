/* chaskey8s.cpp - implementation of Chaskey 8 cipher block
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
#include "chaskey.hpp"
namespace crypto {
namespace chaskey {
void Cipher8s::permute() noexcept {
	base::permute();
}

void Cipher8s::etumrep() noexcept {
	base::etumrep();
}

void Cipher8s::derive(block_t& v, const block_t& in) noexcept {
	base::derive(v,in);
}

}}
