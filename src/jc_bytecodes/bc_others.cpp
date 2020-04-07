/*
** The MIT License (MIT)
**
** Copyright (c) 2020, National Cybersecurity Agency of France (ANSSI)
**
** Permission is hereby granted, free of charge, to any person obtaining a copy
** of this software and associated documentation files (the "Software"), to deal
** in the Software without restriction, including without limitation the rights
** to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
** copies of the Software, and to permit persons to whom the Software is
** furnished to do so, subject to the following conditions:
**
** The above copyright notice and this permission notice shall be included in
** all copies or substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
** OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
** THE SOFTWARE.
**
** Author:
**   - Guillaume Bouffard <guillaume.bouffard@ssi.gouv.fr>
*/

#include "../debug.hpp"
#include "bytecodes.hpp"

namespace jcvm {

extern void callJCNativeMethod(Context &, jshort_t);

/**
 * Do nothing
 *
 * Format:
 *   nop
 *
 * Forms:
 *   nop = 00 (0x00)
 *
 * Stack:
 *   No change.
 *
 * Description:
 *
 *   Do Nothing.
 */
void Bytecodes::bc_nop() {
  TRACE_JCVM_DEBUG("NOP");

  return;
}

/**
 * Call implementation depend 1 instruction
 *
 * Format:
 *   impdep1
 *
 * Forms:
 *   impedp1 = 254 (0xFE)
 *
 * Stack:
 *   ..., index -> ..., [result]
 *
 * Description:
 *
 *   Call native method.
 */
void Bytecodes::bc_impdep1() {
  jshort_t index;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("IMPDEP1");

  index = stack.pop_Short();
  callJCNativeMethod(this->context, index);

  return;
}

/**
 * Call implementation depend 2 instruction
 *
 * Format:
 *   impdep1
 *
 * Forms:
 *   impedp2 = 255 (0xFF)
 *
 * Stack:
 *   ..., index -> ..., [result]
 *
 * Description:
 *
 *   Call native method.
 */
void Bytecodes::bc_impdep2() {
  // jshort_t index;
  // Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("IMPDEP2");

  throw Exceptions::NotYetImplemented;

  return;
}

} // namespace jcvm
