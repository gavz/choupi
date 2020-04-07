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
#include "../jc_handlers/flashmemory.hpp"
#include "../stack.hpp"
#include "bytecodes.hpp"

namespace jcvm {

/**
 * Push null
 *
 * Format:
 *   aconst_null
 *
 * Forms:
 *   aconst_null = 1 (0x1)
 *
 * Stack:
 *   ... -> ..., null
 *
 * Description:
 *
 *   Push the null object reference onto the operand stack.
 */
void Bytecodes::bc_aconst_null() {
  Stack &stack = this->context.getStack();

  jref_t null_ptr(0);

  TRACE_JCVM_DEBUG("ACONST_NULL");

  stack.push_Reference(null_ptr);

  return;
}

/**
 * Push short constant -1
 *
 * Format:
 *   sconst_m1
 *
 * Forms:
 *   sconst_m1 = 2 (0x2)
 *
 * Stack:
 *   ... -> ..., -1
 *
 * Description:
 *
 *   Push the short constant -1 onto the operand stack.
 */
void Bytecodes::bc_sconst_m1() {
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SCONST_M1");

  stack.push_Short((jshort_t)-1);
  return;
}

/**
 * Push short constant 0
 *
 * Format:
 *   sconst_0
 *
 * Forms:
 *   sconst_0 = 3 (0x3)
 *
 * Stack:
 *   ... -> ..., 0
 *
 * Description:
 *
 *   Push the short constant 0 onto the operand stack.
 */
void Bytecodes::bc_sconst_0() {
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SCONST_0");

  stack.push_Short((jshort_t)0);
  return;
}

/**
 * Push short constant 1
 *
 * Format:
 *   sconst_1
 *
 * Forms:
 *   sconst_1 = 4 (0x4)
 *
 * Stack:
 *   ... -> ..., 1
 *
 * Description:
 *
 *   Push the short constant 1 onto the operand stack.
 */
void Bytecodes::bc_sconst_1() {
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SCONST_1");

  stack.push_Short((jshort_t)1);
  return;
}

/**
 * Push short constant 2
 *
 * Format:
 *   sconst_2
 *
 * Forms:
 *   sconst_2 = 5 (0x5)
 *
 * Stack:
 *   ... -> ..., 2
 *
 * Description:
 *
 *   Push the short constant 2 onto the operand stack.
 */
void Bytecodes::bc_sconst_2() {
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SCONST_2");

  stack.push_Short((jshort_t)2);
  return;
}

/**
 * Push short constant 3
 *
 * Format:
 *   sconst_3
 *
 * Forms:
 *   sconst_3 = 6 (0x6)
 *
 * Stack:
 *   ... -> ..., 3
 *
 * Description:
 *
 *   Push the short constant 3 onto the operand stack.
 */
void Bytecodes::bc_sconst_3() {
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SCONST_3");

  stack.push_Short((jshort_t)3);
  return;
}

/**
 * Push short constant 4
 *
 * Format:
 *   sconst_4
 *
 * Forms:
 *   sconst_4 = 7 (0x7)
 *
 * Stack:
 *   ... -> ..., 4
 *
 * Description:
 *
 *   Push the short constant 4 onto the operand stack.
 */
void Bytecodes::bc_sconst_4() {
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SCONST_4");

  stack.push_Short((jshort_t)4);
  return;
}

/**
 * Push short constant 5
 *
 * Format:
 *   sconst_5
 *
 * Forms:
 *   sconst_5 = 8 (0x8)
 *
 * Stack:
 *   ... -> ..., 5
 *
 * Description:
 *
 *   Push the short constant 5 onto the operand stack.
 */
void Bytecodes::bc_sconst_5() {
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SCONST_5");

  stack.push_Short((jshort_t)5);
  return;
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Push int constant -1
 *
 * Format:
 *   iconst_m1
 *
 * Forms:
 *   iconst_m1 = 9 (0x9)
 *
 * Stack:
 *   ... -> ..., (-1).word1, (-1).word2
 *
 * Description:
 *
 *   Push the int constant -1 onto the operand stack.
 */
void Bytecodes::bc_iconst_m1() {
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ICONST_M1");

  stack.push_Int((jint_t)-1);
  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Push int constant 0
 *
 * Format:
 *   iconst_0
 *
 * Forms:
 *   iconst_0 = 10 (0xa)
 *
 * Stack:
 *   ... -> ..., (0).word1, (0).word2
 *
 * Description:
 *
 *   Push the int constant 0 onto the operand stack.
 */
void Bytecodes::bc_iconst_0() {
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ICONST_0");

  stack.push_Int((jint_t)0);
  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Push int constant 1
 *
 * Format:
 *   iconst_1
 *
 * Forms:
 *   iconst_1 = 11 (0xb)
 *
 * Stack:
 *   ... -> ..., (1).word1, (1).word2
 *
 * Description:
 *
 *   Push the int constant 1 onto the operand stack.
 */
void Bytecodes::bc_iconst_1() {
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ICONST_1");

  stack.push_Int((jint_t)1);
  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Push int constant 2
 *
 * Format:
 *   iconst_2
 *
 * Forms:
 *   iconst_2 = 12 (0xc)
 *
 * Stack:
 *   ... -> ..., (2).word1, (2).word2
 *
 * Description:
 *
 *   Push the int constant 2 onto the operand stack.
 */
void Bytecodes::bc_iconst_2() {
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ICONST_2");

  stack.push_Int((jint_t)2);
  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Push int constant 3
 *
 * Format:
 *   iconst_3
 *
 * Forms:
 *   iconst_3 = 13 (0xd)
 *
 * Stack:
 *   ... -> ..., (3).word1, (3).word2
 *
 * Description:
 *
 *   Push the int constant 3 onto the operand stack.
 */
void Bytecodes::bc_iconst_3() {
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ICONST_3");

  stack.push_Int((jint_t)3);
  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Push int constant 4
 *
 * Format:
 *   iconst_4
 *
 * Forms:
 *   iconst_4 = 14 (0xe)
 *
 * Stack:
 *   ... -> ..., (4).word1, (4).word2
 *
 * Description:
 *
 *   Push the int constant 4 onto the operand stack.
 */
void Bytecodes::bc_iconst_4() {
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ICONST_4");

  stack.push_Int((jint_t)4);
  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Push int constant 5
 *
 * Format:
 *   iconst_5
 *
 * Forms:
 *   iconst_5 = 15 (0xf)
 *
 * Stack:
 *   ... -> ..., (5).word1, (5).word2
 *
 * Description:
 *
 *   Push the int constant 5 onto the operand stack.
 */
void Bytecodes::bc_iconst_5() {
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ICONST_5");

  stack.push_Int((jint_t)5);
  return;
}
#endif /* JCVM_INT_SUPPORTED */

/**
 * Push byte
 *
 * Format:
 *   bspush
 *   byte
 *
 * Forms:
 *   bspush = 16 (0x10)
 *
 * Stack:
 *   ... -> ..., value
 *
 * Description:
 *
 *   The immediate byte is sign-extended to a short, and the resulting value
 *   is pushed onto the operand stack.
 */
void Bytecodes::bc_bspush() {
  jbyte_t value;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = pc.getNextByte();

  TRACE_JCVM_DEBUG("BSPUSH 0x%02X", value);

  stack.push_Short((jshort_t)value);
  return;
}

/**
 * Push short
 *
 * Format:
 *   sspush
 *   byte1
 *   byte2
 *
 * Forms:
 *   sspush = 17 (0x11)
 *
 * Stack:
 *   ... -> ..., value
 *
 * Description:
 *
 *    The immediate unsigned byte1 and byte2 values are assembled into a
 *    signed short where the value of the short is (byte1 << 8) | byte2. The
 *    resulting value is pushed onto the operand stack.
 */
void Bytecodes::bc_sspush() {
  jshort_t value;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = pc.getNextShort();

  TRACE_JCVM_DEBUG("SSPUSH 0x%02X", value);

  stack.push_Short(value);

  return;
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Push byte
 *
 * Format:
 *   bipush
 *   byte
 *
 * Forms:
 *   bipush = 18 (0x12)
 *
 * Stack:
 *   ... -> ..., value.word1, value.word2
 *
 * Description:
 *
 *    The immediate byte is sign-extended to an int, and the resulting value
 *    is pushed onto the operand stack.
 *
 * Note:
 *
 *  If a virtual machine does not support the int data type, the bipush
 *  instruction will not be available.
 */
void Bytecodes::bc_bipush() {
  jbyte_t value;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = pc.getNextByte();

  TRACE_JCVM_DEBUG("BIPUSH 0x%02X", value);

  stack.push_Int((jint_t)value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Push short
 *
 * Format:
 *   sipush
 *   byte1
 *   byte2
 *
 * Forms:
 *   sipush = 19 (0x13)
 *
 * Stack:
 *   ... -> ..., value1.word1, value1.word2
 *
 * Description:
 *
 *   The immediate unsigned byte1 and byte2 values are assembled into a
 *   signed short where the value of the short is (byte1 << 8) | byte2. The
 *   intermediate value is then sign-extended to an int, and the resulting
 *   value is pushed onto the operand stack.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the sipush
 *   instruction will not be available.
 */
void Bytecodes::bc_sipush() {
  jshort_t value;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = pc.getNextShort();

  TRACE_JCVM_DEBUG("SIPUSH 0x%02X", value);

  stack.push_Int((jint_t)value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Push int
 *
 * Format:
 *   iipush
 *   byte1
 *   byte2
 *   byte3
 *   byte4
 *
 * Forms:
 *   iipush = 20 (0x14)
 *
 * Stack:
 *   ... -> ..., value1.word1, value1.word2
 *
 * Description:
 *
 *   The immediate unsigned byte1, byte2, byte3, and byte4 values are
 *   assembled into a signed int where the value of the int is (byte1 << 24)
 *   | (byte2 << 16) | (byte3 << 8) | byte4. The resulting value is pushed
 *   onto the operand stack.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the iipush
 *   instruction will not be available.
 */
void Bytecodes::bc_iipush() {
  jint_t value;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = pc.getNextInt();

  TRACE_JCVM_DEBUG("IIPUSH 0x%02X", value);

  stack.push_Int(value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

} // namespace jcvm
