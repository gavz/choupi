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
#include "../jc_utils.hpp"
#include "../stack.hpp"
#include "bytecodes.hpp"

namespace jcvm {

/**
 * Pop top operand stack word
 *
 * Format:
 *   pop
 *
 * Forms:
 *   pop = 59 (0x3b)
 *
 * Stack:
 *   ..., word -> ...
 *
 * Description:
 *
 *   The top word is popped from the operand stack. The pop instruction must
 *   not be used unless the word contains a 16-bit data type.
 *
 * Notes:
 *
 *   The pop instruction operates on an untyped word, ignoring the type of
 *   data it contains.
 */
void Bytecodes::bc_pop() {
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("POP");

  stack.pop();

  return;
}

/**
 * Pop top two operand stack words
 *
 * Format:
 *   pop
 *
 * Forms:
 *   pop = 60 (0x3c)
 *
 * Stack:
 *   ..., word2, word1 -> ...
 *
 * Description:
 *
 *   The top two words are popped from the operand stack.
 *
 *   The pop2 instruction must not be used unless each of word1 and word2 is
 *   a word that contains a 16-bit data type or both together are the two
 *   words of a single 32-bit datum.
 *
 * Notes:
 *
 *   Except for restrictions preserving the integrity of 32-bit data types,
 *   the pop2 instruction operates on an untyped word, ignoring the type of
 *   data it contains.
 */
void Bytecodes::bc_pop2() {
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("POP2");

  stack.pop();
  stack.pop();

  return;
}

/**
 * Duplicate top operand stack word
 *
 * Format:
 *   dup
 *
 * Forms:
 *   dup = 61 (0x3d)
 *
 * Stack:
 *   ..., word -> ..., word, word
 *
 * Description:
 *
 *   The top word on the operand stack is duplicated and pushed onto the
 *   operand stack. The dup instruction must not be used unless word
 *   contains a 16-bit data type.
 *
 * Notes:
 *
 *   Except for restrictions preserving the integrity of 32-bit data types,
 *   the dup instruction operates on an untyped word, ignoring the type of
 *   data it contains.
 */
void Bytecodes::bc_dup() {
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("DUP");

  stack.dup(1, 0);

  return;
}

/**
 * Duplicate top two operand stack words
 *
 * Format:
 *   dup2
 *
 * Forms:
 *   dup2 = 62 (0x3e)
 *
 * Stack:
 *   ..., word2, word1 -> ..., word2, word1, word2, word1
 *
 * Description:
 *
 *   The top two words on the operand stack are duplicated and pushed onto
 *   the operand stack, in the original order.
 *
 *   The dup2 instruction must not be used unless each of word1 and word2 is
 *   a word that contains a 16-bit data type or both together are the two
 *   words of a single 32-bit datum.
 *
 * Notes:
 *
 *   Except for restrictions preserving the integrity of 32-bit data types,
 *   the dup2 instruction operates on untyped words, ignoring the types of
 *   data they contain.
 */
void Bytecodes::bc_dup2() {
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("DUP2");

  stack.dup(2, 0);

  return;
}

/**
 * Duplicate top operand stack words and insert below
 *
 * Format:
 *   dup_x
 *   mn
 *
 * Forms:
 *   dup_x = 63 (0x3f)
 *
 * Stack:
 *   ..., wordN, ..., wordM, ..., word1 ->
 *                  ..., wordM, ..., word1, wordN, ..., wordM, ..., word1
 *
 * Description:
 *
 *   The unsigned byte mn is used to construct two parameter values. The
 *   high nibble, (mn & 0xf0) >> 4, is used as the value m. The low nibble,
 *   (mn & 0xf), is used as the value n. Permissible values for m are 1
 *   through 4. Permissible values for n are 0 and m through m+4.
 *
 *   For positive values of n, the top m words on the operand stack are
 *   duplicated and the copied words are inserted n words down in the
 *   operand stack. When n equals 0, the top m words are copied and placed
 *   on top of the stack.
 *
 *   The dup_x instruction must not be used unless the ranges of words 1
 *   through m and words m+1 through n each contain either a 16-bit data
 *   type, two 16-bit data types, a 32-bit data type, a 16-bit data type and
 *   a 32-bit data type (in either order), or two 32-bit data types.
 *
 * Notes:
 *
 *   Except for restrictions preserving the integrity of 32-bit data types,
 *   the dup_x instruction operates on untyped words, ignoring the types of
 *   data they contain.
 *
 *   If a virtual machine does not support the int data type, the
 *   permissible values for m are 1 or 2, and permissible values for n are 0
 *   and m through m+2.
 */
void Bytecodes::bc_dup_x() {
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  jbyte_t mn;
  uint8_t m;
  uint8_t n;

  mn = pc.getNextByte();

  TRACE_JCVM_DEBUG("DUP_X 0x%02X", mn);

  m = (uint8_t)HIGH_NIBBLE(mn);
  n = (uint8_t)LOW_NIBBLE(mn);

  TRACE_JCVM_DEBUG("(m = %u, n = %u)", m, n);

#ifdef JCVM_INT_SUPPORTED

  // checking m value. 1 <= m <= 4
  if ((m < 1) || (m > 4)) {
    throw Exceptions::RuntimeException;
  }

  // checking n value. Permissible values for n are 0 and m through m+4.
  if (!((n == 0) || ((m <= n) && (n < (m + 4))))) {
    // Incorrect n value
    throw Exceptions::RuntimeException;
  }

#else /* !JCVM_INT_SUPPORTED */

  // checking m value.
  if ((m != 1) && (m != 2)) {
    // Incorrect m value
    throw Exceptions::RuntimeException;
  }

  // checking n value.
  if ((n != 0) && (n < m) && (n < (m + 2))) {
    // Incorrect n value
    throw Exceptions::RuntimeException;
  }

#endif /* JCVM_INT_SUPPORTED */

  stack.dup(m, n);

  return;
}

/**
 * Swap top two operand stack words
 *
 * Format:
 *   swap_x
 *   mn
 *
 * Forms:
 *   swap_x = 64 (0x40)
 *
 * Stack:
 *   ..., wordM+N, ..., wordM+1, wordM, ..., word1 ->
 *                     ..., wordM, ..., word1, wordM+N, ..., wordM+1
 *
 * Description:
 *
 *   The unsigned byte mn is used to construct two parameter values. The
 *   high nibble, (mn & 0xf0) >> 4, is used as the value m. The low nibble,
 *   (mn & 0xf), is used as the value n. Permissible values for both m and n
 *   are 1 and 2.
 *
 *   The top m words on the operand stack are swapped with the n words
 *   immediately below.
 *
 *   The swap_x instruction must not be used unless the ranges of words 1
 *   through m and words m+1 through n each contain either a 16-bit data
 *   type, two 16-bit data types, a 32-bit data type, a 16-bit data type and
 *   a 32-bit data type (in either order), or two 32-bit data types.
 *
 * Notes:
 *
 *   Except for restrictions preserving the integrity of 32-bit data types,
 *   the swap_x instruction operates on untyped words, ignoring the types of
 *   data they contain.
 *
 *   If a virtual machine does not support the xint data type, the only
 *   permissible value for both m and n is 1.
 */
void Bytecodes::bc_swap_x() {
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  jbyte_t mn;
  uint8_t m;
  uint8_t n;

  mn = pc.getNextByte();

  TRACE_JCVM_DEBUG("SWAP_X 0x%02X", mn);

  m = (uint8_t)(mn & 0xF0) >> 4;
  n = (uint8_t)(mn & 0x0F);

  TRACE_JCVM_DEBUG("(m = %u, n = %u)", m, n);

  stack.swap(m, n);
  return;
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Compare int
 *
 * Format:
 *   icmp
 *
 * Forms:
 *   icmp = 95 (0x5f)
 *
 * Stack:
 *   ..., value.word1, value.word2 -> ..., result
 *
 * Description:
 *
 *   Both value1 and value2 must be of type int. They are both popped from
 *   the operand stack, and a signed integer comparison is performed. If
 *   value1 is greater than value2, the short value 1 is pushed onto the
 *   operand stack. If value1 is equal to value2, the short value 0 is
 *   pushed onto the operand stack. If value1 is less than value2, the short
 *   value -1 is pushed onto the operand stack.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the ineg
 *   instruction will not be available.
 */
void Bytecodes::bc_icmp() {
  Stack &stack = this->context.getStack();

  jint_t value1;
  jint_t value2;

  TRACE_JCVM_DEBUG("ICMP");

  value2 = stack.pop_Int();
  value1 = stack.pop_Int();

  if (value1 > value2) {
    stack.push_Short((jshort_t)1);
  } else if (value1 == value2) {
    stack.push_Short((jshort_t)0);
  } else { // value1 < value2
    stack.push_Short((jshort_t)-1);
  }

  return;
}
#endif /* JCVM_INT_SUPPORTED */

} // namespace jcvm
