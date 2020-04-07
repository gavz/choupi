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
#include <limits>

namespace jcvm {

#ifdef JCVM_INT_SUPPORTED
/**
 * Convert int to byte
 *
 * Format:
 *   i2b
 *
 * Forms:
 *   i2b = 93 (0x5d)
 *
 * Stack:
 *   ..., value.word1, value.word2 -> ..., result
 *
 * Description:
 *
 *   The value on top of the operand stack must be of type int. It is popped
 *   from the operand stack and converted to a byte result by taking the
 *   low-order 16 bits of the int value, and discarding the high-order 16
 *   bits. The low-order word is truncated to a byte, then sign-extended to
 *   a short result. The result is pushed onto the operand stack.
 *
 * Notes:
 *
 *   The i2b instruction performs a narrowing primitive conversion. It may
 *   lose information about the overall magnitude of value. The result may
 *   also not have the same sign as value.
 *
 *   If a virtual machine does not support the int data type, the i2b
 *   instruction will not be available.
 *
 */
void Bytecodes::bc_i2b() {
  jint_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("I2B");

  value = stack.pop_Int();
  stack.push_Byte((jbyte_t)value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Convert int to short
 *
 * Format:
 *   i2s
 *
 * Forms:
 *   i2s = 94 (0x5e)
 *
 * Stack:
 *   ..., value.word1, value.word2 -> ..., result
 *
 * Description:
 *
 *   The value on top of the operand stack must be of type int. It is popped
 *   from the operand stack and converted to a short result by taking the
 *   low-order 16 bits of the int value and discarding the high-order 16
 *   bits. The result is pushed onto the operand stack.
 *
 * Notes:
 *
 *   The i2s instruction performs a narrowing primitive conversion. It may
 *   lose information about the overall magnitude of value. The result may
 *   also not have the same sign as value.
 *
 *   If a virtual machine does not support the int data type, the i2b
 *   instruction will not be available.
 *
 */
void Bytecodes::bc_i2s() {
  jint_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("I2S");

  value = stack.pop_Int();
  stack.push_Short((jshort_t)value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Add int
 *
 * Format:
 *   iadd
 *
 * Forms:
 *   iadd = 66 (0x42)
 *
 * Stack:
 *   ..., value1.word1, value1.word2, value2.word1, value2.word2 ->
 *                                          ..., result.word1, result.word2
 *
 * Description:
 *
 *   Both value1 and value2 must be of type int. The values are popped from
 *   the operand stack. The int result is value1 + value2. The result is
 *   pushed onto the operand stack.
 *
 *   If an iadd instruction overflows, then the result is the low-order bits
 *   of the true mathematical result in a sufficiently wide two’s-complement
 *   format. If overflow occurs, then the sign of the result may not be the
 *   same as the sign of the mathematical sum of the two values.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the iadd
 *   instruction will not be available.
 */
void Bytecodes::bc_iadd() {
  jint_t value1;
  jint_t value2;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("IADD");

  value2 = stack.pop_Int();
  value1 = stack.pop_Int();

  stack.push_Int((jint_t)(value1 + value2));

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Boolean AND int
 *
 * Format:
 *   iand
 *
 * Forms:
 *   iand = 85 (0x55)
 *
 * Stack:
 *   ..., value1.word1, value1.word2, value2.word1, value2.word2 ->
 *                                            ..., result.word1, result.word2
 *
 * Description:
 *
 *   Both value1 and value2 must be of type int. They are popped from the
 *   operand stack. An int result is calculated by taking the bitwise AND
 *   (conjunction) of value1 and value2. The result is pushed onto the
 *   operand stack.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the iand
 *   instruction will not be available.
 *
 */
void Bytecodes::bc_iand() {
  jint_t value1, value2;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("IAND");

  value2 = stack.pop_Int();
  value1 = stack.pop_Int();

  stack.push_Int((jint_t)(value1 & value2));

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED

/**
 * Divide int
 *
 * Format:
 *   idiv
 *
 * Forms:
 *   idiv = 72 (0x48)
 *
 * Stack:
 *   ..., value1.word1, value1.word2, value2.word1, value2.word2 ->
 *                                           ..., result.word1, result.word2
 *
 * Description:
 *
 *   Both value1 and value2 must be of type int. The values are popped from
 *   the operand stack. The int result is the value of the Java expression
 *   value1 / value2. The result is pushed onto the operand stack.
 *
 *   An int division rounds towards 0; that is, the quotient produced for
 *   int values in n/d is an int value q whose magnitude is as large as
 *   possible while satisfying | d · q | <= | n |. Moreover, q is a positive
 *   when | n | >= | d | and n and d have the same sign, but q is negative
 *   when | n | >= | d | and n and d have opposite signs.
 *
 *   There is one special case that does not satisfy this rule: if the
 *   dividend is the negative integer of the largest possible magnitude for
 *   the int type, and the divisor is -1, then overflow occurs, and the
 *   result is equal to the dividend. Despite the overflow, no exception is
 *   thrown in this case.
 *
 * Runtime Exception:
 *
 *   If the value of the divisor in an int division is 0, idiv throws an
 *   ArithmeticException.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the idiv
 *   instruction will not be available.
 */
void Bytecodes::bc_idiv() {
  jint_t value1;
  jint_t value2;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("IDIV");

  value2 = stack.pop_Int();
  value1 = stack.pop_Int();

  if (value2 == 0) { // division by 0
    throw Exceptions::ArithmeticException;
  } else if ((value1 == std::numeric_limits<jint_t>::min()) &&
             (value2 == (jint_t)-1)) {
    stack.push_Int((jint_t)(0));
  } else {
    stack.push_Int((jint_t)(value1 / value2));
  }

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Increment local int variable by constant
 *
 * Format:
 *   iinc
 *   index
 *   const
 *
 * Forms:
 *   iinc = 90 (0x5a)
 *
 * Stack:
 *   No change
 *
 * Description:
 *
 *   The index is an unsigned byte. Both index and index + 1 must be valid
 *   indices into the local variables of the current frame (§3.5 Frames).
 *   The local variables at index and index + 1 together must contain an
 *   int. The const is an immediate signed byte. The value const is first
 *   sign-extended to an int, then the int contained in the local variables
 *   at index and index + 1 is incremented by that amount.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the iinc
 *   instruction will not be available.
 */
void Bytecodes::bc_iinc() {
  uint8_t index;
  int8_t const_value;
  jint_t local_value;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();
  const_value = pc.getNextByte();

  TRACE_JCVM_DEBUG("IINC 0x%02X 0x%02X", index, const_value);

  local_value = stack.readLocal_Int(index);
  local_value += const_value;
  stack.writeLocal_Int(index, local_value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Increment local int variable by constant
 *
 * Format:
 *   iinc_w
 *   index
 *   byte1
 *   byte2
 *
 * Forms:
 *   iinc_w = 151 (0x97)
 *
 * Stack:
 *   No change
 *
 * Description:
 *
 *   The index is an unsigned byte. Both index and index + 1 must be valid
 *   indices into the local variables of the current frame (§3.5 Frames).
 *   The local variables at index and index + 1 together must contain an
 *   int. The immediate unsigned byte1 and byte2 values are assembled into
 *   an intermediate short where the value of the short is (byte1 << 8) |
 *   byte2. The intermediate value is then sign-extended to an int const.
 *   The int contained in the local variables at index and index + 1 is
 *   incremented by const.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the iinc_w
 *   instruction will not be available.
 */
void Bytecodes::bc_iinc_w() {
  uint8_t index;
  int16_t const_value;
  jint_t local_value;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();
  const_value = pc.getNextShort();

  TRACE_JCVM_DEBUG("IINC_W 0x%02X 0x%04X", index, const_value);

  local_value = stack.readLocal_Int(index);
  local_value += const_value;

  stack.writeLocal_Int(index, local_value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Multiply int
 *
 * Format:
 *   imul
 *
 * Forms:
 *   imull = 70 (0x46)
 *
 * Stack:
 *
 *   ..., value1.word1, value1.word2, value2.word1, value2.word2 ->
 *                                           ..., result.word1, result.word2
 *
 * Description:
 *
 *   Both value1 and value2 must be of type int. The values are popped from
 *   the operand stack. The int result is value1 * value2. The result is
 *   pushed onto the operand stack.
 *
 *   If an imul instruction overflows, then the result is the low-order bits
 *   of the mathematical product as an int. If overflow occurs, then the
 *   sign of the result may not be the same as the sign of the mathematical
 *   product of the two values.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the imul
 *   instruction will not be available.
 */
void Bytecodes::bc_imul() {
  jint_t value1;
  jint_t value2;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("IMUL");

  value2 = stack.pop_Int();
  value1 = stack.pop_Int();
  stack.push_Int((jint_t)(value1 * value2));

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Negate int
 *
 * Format:
 *   ineg
 *
 * Forms:
 *   ineg = 76 (0x4c)
 *
 * Stack:
 *   ..., value.word1, value.word2 -> ..., result.word1, result.word2
 *
 * Description:
 *
 *   The value must be of type int. It is popped from the operand stack. The
 *   int result is the arithmetic negation of value, -value. The result is
 *   pushed onto the operand stack.
 *
 *   For int values, negation is the same as subtraction from zero. Because
 *   the Java Card virtual machine uses two's-complement representation for
 *   integers and the range of two's-complement values is not symmetric, the
 *   negation of the maximum negative int results in that same maximum
 *   negative number. Despite the fact that overflow has occurred, no
 *   exception is thrown.
 *
 *   For all int values x, -x equals (~x) + 1.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the ineg
 *   instruction will not be available.
 */
void Bytecodes::bc_ineg() {
  jint_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("INEG");

  value = stack.pop_Int();
  stack.push_Int(-value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Boolean OR int
 *
 * Format:
 *   ior
 *
 * Forms:
 *   ior = 86 (0x56)
 *
 * Stack:
 *   ..., value1.word1, value1.word2, value2.word1, value2.word2 ->
 *                                         ..., result.word1, result.word2
 *
 * Description:
 *
 *   Both value1 and value2 must be of type int. The values are popped from
 *   the operand stack. An int result is calculated by taking the bitwise
 *   inclusive OR of value1 and value2. The result is pushed onto the
 *   operand stack.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the ior
 *   instruction will not be available.
 *
 */
void Bytecodes::bc_ior() {
  jint_t value1, value2;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("IOR");

  value2 = stack.pop_Int();
  value1 = stack.pop_Int();

  stack.push_Int((jint_t)(value1 | value2));

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED

/**
 *Remainder int
 *
 *Format:
 *  irem
 *
 *Forms:
 *  irem = 74 (0x4a)
 *
 *Stack:
 *  ..., value1.word1, value1.word2, value2.word1, value2.word2 ->
 *                                          ..., result.word1, result.word2
 *
 *Description:
 *
 *  Both value1 and value2 must be of type int. The values are popped from
 *  the operand stack. The int result is the value of the Java expression
 *  value1 - (value1 / value2) * value2. The result is pushed onto the
 *  operand stack.
 *
 *  The result of the irem instruction is such that (a/b)*b + (a%b) is
 *  equal to a. This identity holds even in the special case that the
 *  dividend is the negative int of largest possible magnitude for its type
 *  and the divisor is -1 (the remainder is 0). It follows from this rule
 *  that the result of the remainder operation can be negative only if the
 *  dividend is negative and can be positive only if the dividend is
 *  positive. Moreover, the magnitude of the result is always less than the
 *  magnitude of the divisor.
 *
 *Runtime Exception:
 *
 *  If the value of the divisor for a short remainder operator is 0, irem
 *  throws an ArithmeticException.
 *
 *Notes:
 *
 *  If a virtual machine does not support the int data type, the irem
 *  instruction will not be available.
 */
void Bytecodes::bc_irem() {
  jint_t value1;
  jint_t value2;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("IREM");

  value2 = stack.pop_Int();
  value1 = stack.pop_Int();

  if (value2 == 0) { // division by 0
    throw Exceptions::ArithmeticException;
  } else if ((value1 == std::numeric_limits<jint_t>::min()) &&
             (value2 == (jint_t)-1)) {
    stack.push_Int((jint_t)(0));
  } else {
    stack.push_Int((jint_t)(value1 % value2));
  }

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Shift left int
 *
 * Format:
 *   ishl
 *
 * Forms:
 *   ishl = 78 (0x4e)
 *
 * Stack:
 *   ..., value1.word1, value1.word2, value2.word1, value2.word2 -> ...,
 * result.word1, result.word2
 *
 * Description:
 *
 *   Both value1 and value2 must be of type int. The values are popped from
 *   the operand stack. An int result is calculated by shifting value1 left
 *   by s bit positions, where s is the value of the low five bits of
 *   value2. The result is pushed onto the operand stack.
 *
 * Notes:
 *
 *   This is equivalent (even if overflow occurs) to multiplication by 2 to
 *   the power s. The shift distance actually used is always in the range 0
 *   to 31, inclusive, as if value2 were subjected to a bitwise logical AND
 *   with the mask value 0x1f.
 *
 *   If a virtual machine does not support the int data type, the ishl
 *   instruction will not be available.
 */
void Bytecodes::bc_ishl() {
  jint_t value1, value2;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ISHL");

  value2 = stack.pop_Int();
  value1 = stack.pop_Int();

  /**
   * C-language Standard:
   *
   * The result of E1 << E2 is E1 left-shifted E2 bit positions; vacated
   * bits are filled with zeros. If E1 has an unsigned type, the value of
   * the result is E1 × 2^E2 , reduced modulo one more than the maximum
   * value representable in the result type. If E1 has a signed type and
   * nonnegative value, and E1 × 2^E2 is representable in the result type,
   * then that is the resulting value; otherwise, the behavior is
   * undefined.
   *
   * [source: ISO/IEC 9899, §6.5.7 -- Bitwise shift operators]
   */

  stack.push_Int(value1 << (value2 & 0x1f));

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 *Arithmetic shift right int
 *
 *Format:
 *  ishr
 *
 *Forms:
 *  ishr = 80 (0x50)
 *
 *Stack:
 *  ..., value1.word1, value1.word2, value2.word1, value2.word2 ->
 *                                           ..., result.word1, result.word2
 *
 *Description:
 *
 *  Both value1 and value2 must be of type int. The values are popped from
 *  the operand stack. An int result is calculated by shifting value1 right
 *  by s bit positions, with sign extension, where s is the value of the
 *  low five bits of value2. The result is pushed onto the operand stack.
 *
 *Notes:
 *
 *  The resulting value is ⌊value1/2^s⌋, where s is value2 & 0x1f. For
 *  nonnegative value1, this is equivalent (even if overflow occurs) to
 *  truncating int division by 2 to the power s. The shift distance
 *  actually used is always in the range 0 to 31, inclusive, as if value2
 *  were subjected to a bitwise logical AND with the mask value 0x1f.
 *
 *  If a virtual machine does not support the int data type, the ishl
 *  instruction will not be available.
 */
void Bytecodes::bc_ishr() {
  jint_t value1, value2;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ISHR");

  value2 = stack.pop_Int();
  value1 = stack.pop_Int();

  /*
   * C-language Standard:
   *
   * The result of E1 >> E2 is E1 right-shifted E2 bit positions. If E1
   * has an unsigned type or if E1 has a signed type and a nonnegative
   * value, the value of the result is the integral part of the quotient
   * of E1/(2^E2). If E1 has a signed type and a negative value, the
   * resulting value is implementation-defined.
   *
   * [source: ISO/IEC 9899, §6.5.7 -- Bitwise shift operators]
   */

  // In ISO C, the operator >> is toolchain/platform dependent for
  // negative values
  if (value1 < 0) {
    stack.push_Int((jint_t)(~((~value1) >> (value2 & 0x1f))));
  } else {
    stack.push_Int((jint_t)(value1 >> (value2 & 0x1f)));
  }

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Subtract int
 *
 * Format:
 *   isub
 *
 * Forms:
 *   isub = 68 (0x44)
 *
 * Stack:
 *   ..., value1.word1, value1.word2, value2.word1, value2.word2 ->
 *                                           ..., result.word1, result.word2
 *
 * Description:
 *
 *   Both value1 and value2 must be of type int. The values are popped from
 *   the operand stack. The int result is value1 - value2. The result is
 *   pushed onto the operand stack.
 *
 *   For int subtraction, a - b produces the same result as a + (-b). For
 *   int values, subtraction from zeros is the same as negation.
 *
 *   Despite the fact that overflow or underflow may occur, in which case
 *   the result may have a different sign than the true mathematical result,
 *   execution of an isub instruction never throws a runtime exception.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the isub
 *   instruction will not be available.
 */
void Bytecodes::bc_isub() {
  jint_t value1;
  jint_t value2;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ISUB");

  value2 = stack.pop_Int();
  value1 = stack.pop_Int();
  stack.push_Int((jint_t)(value1 - value2));

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 *Logical shift right int
 *
 *Format:
 *  iushr
 *
 *Forms:
 *  iushr = 82 (0x52)
 *
 *Stack:
 *  ..., value1.word1, value1.word2, value2.word1, value2.word2 ->
 *                                             ..., result.word1, result.word2
 *
 *Description:
 *
 *  Both value1 and value2 must be of type int. The values are popped from
 *  the operand stack. An int result is calculated by shifting the result
 *  right by s bit positions, with zero extension, where s is the value of
 *  the low five bits of value2. The result is pushed onto the operand
 *  stack.
 *
 *Notes:
 *
 *  If value1 is positive and s is value2 & 0x1f, the result is the same as
 *  that of value1 >> s; if value1 is negative, the result is equal to the
 *  value of the expression (value1 >> s) + (2 << ~s). The addition of the
 *  (2 << ~s) term cancels out the propagated sign bit. The shift distance
 *  actually used is always in the range 0 to 31, inclusive, as if value2
 *  were subjected to a bitwise logical AND with the mask value 0x1f.
 *
 *  If a virtual machine does not support the int data type, the iushr
 *  instruction will not be available.
 */
void Bytecodes::bc_iushr() {
  jint_t value, s;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("IUSHR");

  s = stack.pop_Int() & 0x1F;
  value = stack.pop_Int();

  if (value > 0) {
    stack.push_Int((jint_t)(value >> s));
  } else {
    stack.push_Int((jint_t)((value >> s) + (2 << ~s)));
  }

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Boolean XOR int
 *
 * Format:
 *   ixor
 *
 * Forms:
 *   ixor = 88 (0x58)
 *
 * Stack:
 *   ..., value1.word1, value1.word2, value2.word1, value2.word2 ->
 *                                        ..., result.word1, result.word2
 *
 * Description:
 *
 *   Both value1 and value2 must be of type int. The values are popped from
 *   the operand stack. An int result is calculated by taking the bitwise
 *   exclusive OR of value1 and value2. The result is pushed onto the
 *   operand stack.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the ixor
 *   instruction will not be available.
 *
 */
void Bytecodes::bc_ixor() {
  jint_t value1, value2;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("IXOR");

  value2 = stack.pop_Int();
  value1 = stack.pop_Int();

  stack.push_Int((jint_t)(value1 ^ value2));

  return;
}
#endif /* JCVM_INT_SUPPORTED */

/**
 * Convert short to byte
 *
 * Format:
 *   s2b
 *
 * Forms:
 *   s2b = 91 (0x5b)
 *
 * Stack:
 *   ..., value -> ..., result
 *
 * Description:
 *
 *   The value on top of the operand stack must be of type short. It is
 *   popped from the top of the operand stack, truncated to a byte result,
 *   then sign-extended to a short result. The result is pushed onto the
 *   operand stack.
 *
 * Notes:
 *
 *   The s2b instruction performs a narrowing primitive conversion. It may
 *   lose information about the overall magnitude of value. The result may
 *   also not have the same sign as value.
 */
void Bytecodes::bc_s2b() {
  jbyte_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("S2B");

  value = stack.pop_Byte();

  stack.push_Short((jshort_t)value);

  return;
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Convert short to int
 *
 * Format:
 *   s2i
 *
 * Forms:
 *   s2i = 92 (0x5c)
 *
 * Stack:
 *   ..., value -> ..., result.word1, result.word2
 *
 * Description:
 *
 *   The value on top of the operand stack must be of type short. It is
 *   popped from the operand stack and sign-extended to an int result. The
 *   result is pushed onto the operand stack.
 *
 * Notes:
 *
 *   The s2i instruction performs a widening primitive conversion. Because
 *   all values of type short are exactly representable by type int, the
 *   conversion is exact.
 *
 *   If a virtual machine does not support the int data type, the s2i
 *   instruction will not be available.
 */
void Bytecodes::bc_s2i() {
  jshort_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("S2I");

  value = stack.pop_Short();

  stack.push_Int((jint_t)value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

/**
 * Add short
 *
 * Format:
 *   sadd
 *
 * Forms:
 *   sadd = 65 (0x41)
 *
 * Stack:
 *   ..., value1, value2 -> ..., result
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. The values are popped
 *   from the operand stack. The short result is value1 + value2. The result
 *   is pushed onto the operand stack. If a sadd instruction overflows, then
 *   the result is the low-order bits of the true mathematical result in a
 *   sufficiently wide two's-complement format. If overflow occurs, then the
 *   sign of the result may not be the same as the sign of the mathematical
 *   sum of the two values.
 */
void Bytecodes::bc_sadd() {
  jshort_t value1;
  jshort_t value2;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SADD");

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();
  stack.push_Short((jshort_t)(value1 + value2));

  return;
}

/**
 * Boolean AND short
 *
 * Format:
 *   sand
 *
 * Forms:
 *   sand = 83 (0x53)
 *
 * Stack:
 *   ..., value1, value2 -> ..., result
 *
 * Description:
 *
 *   Both value1 and value2 are popped from the operand stack. A short
 *   result is calculated by taking the bitwise AND (conjunction) of value1
 *   and value2. The result is pushed onto the operand stack.
 *
 */
void Bytecodes::bc_sand() {
  jshort_t value1, value2;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SAND");

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();

  stack.push_Short((jshort_t)(value1 & value2));

  return;
}

/**
 * Divide short
 *
 * Format:
 *   sdiv
 *
 * Forms:
 *   sdiv = 71 (0x47)
 *
 * Stack:
 *   ..., value1, value2 -> ..., result
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. The values are popped
 *   from the operand stack. The short result is the value of the Java
 *   expression value1 / value2. The result is pushed onto the operand
 *   stack.
 *
 *   A short division rounds towards 0; that is, the quotient produced for
 *   short values in n/d is a short value q whose magnitude is as large as
 *   possible while satisfying | d · q | <= | n |. Moreover, q is a positive
 *   when | n | >= | d | and n and d have the same sign, but q is negative
 *   when | n | >= | d | and n and d have opposite signs.
 *
 * Runtime Exception:
 *
 *   If the value of the divisor in a short division is 0, sdiv throws an
 *   ArithmeticException.
 *
 */
void Bytecodes::bc_sdiv() {
  jshort_t value1;
  jshort_t value2;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SDIV");

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();

  if (value2 == 0) { // division by 0
    throw Exceptions::ArithmeticException;
  } else if ((value1 == std::numeric_limits<jshort_t>::min()) &&
             (value2 == (jshort_t)-1)) {
    stack.push_Short((jshort_t)(0));
  } else {
    stack.push_Short((jshort_t)(value1 / value2));
  }

  return;
}

/**
 * Increment local short variable by constant
 *
 * Format:
 *   sinc
 *   index
 *   const
 *
 * Forms:
 *   sinc = 89 (0x59)
 *
 * Stack:
 *   No change
 *
 * Description:
 *
 *   The index is an unsigned byte that must be a valid index into the local
 *   variable of the current frame (§3.5 Frames). The const is an immediate
 *   signed byte. The local variable at index must contain a short. The
 *   value const is first sign-extended to a short, then the local variable
 *   at index is incremented by that amount.
 */
void Bytecodes::bc_sinc() {
  uint8_t index;
  int8_t const_value;
  jshort_t local_value;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();
  const_value = pc.getNextByte();

  TRACE_JCVM_DEBUG("SINC 0x%02X 0x%02X", index, const_value);

  local_value = stack.readLocal_Short(index);
  local_value += const_value;
  stack.writeLocal_Short(index, local_value);

  return;
}

/**
 * Increment local short variable by constant
 *
 * Format:
 *   sinc
 *   index
 *   byte1
 *   byte2
 *
 * Forms:
 *   sinc = 150 (0x96)
 *
 * Stack:
 *   No change
 *
 * Description:
 *
 *   The index is an unsigned byte that must be a valid index into the local
 *   variable of the current frame (§3.5 Frames). The immediate unsigned
 *   byte1 and byte2 values are assembled into a short const where the value
 *   of const is (byte1 << 8) | byte2. The local variable at index, which
 *   must contain a short, is incremented by const.
 */
void Bytecodes::bc_sinc_w() {
  uint8_t index;
  int16_t const_value;
  jshort_t local_value;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();
  const_value = pc.getNextShort();

  TRACE_JCVM_DEBUG("SINC_W 0x%02X 0x%04X", index, const_value);

  local_value = stack.readLocal_Short(index);
  local_value += const_value;
  stack.writeLocal_Short(index, local_value);

  return;
}

/**
 * Multiply short
 *
 * Format:
 *   smul
 *
 * Forms:
 *   smul = 69 (0x45)
 *
 * Stack:
 *   ..., value1, value2 -> ..., result
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. The values are popped
 *   from the operand stack. The short result is value1 * value2. The result
 *   is pushed onto the operand stack.
 *
 *   If a smul instruction overflows, then the result is the low-order bits
 *   of the mathematical product as a short. If overflow occurs, then the
 *   sign of the result may not be the same as the sign of the mathematical
 *   product of the two values.
 */
void Bytecodes::bc_smul() {
  jshort_t value1;
  jshort_t value2;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SMUL");

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();
  stack.push_Short((jshort_t)(value1 * value2));

  return;
}

/**
 * Negate short
 *
 * Format:
 *   sneg
 *
 * Forms:
 *   sneg = 72 (0x4b)
 *
 * Stack:
 *   ..., value -> ..., result
 *
 * Description:
 *
 *   The value must be of type short. It is popped from the operand stack.
 *   The short result is the arithmetic negation of value, -value. The
 *   result is pushed onto the operand stack.
 *
 *   For short values, negation is the same as subtraction from zero.
 *   Because the Java Card virtual machine uses two's-complement
 *   representation for integers and the range of two's-complement values is
 *   not symmetric, the negation of the maximum negative short results in
 *   that same maximum negative number. Despite the fact that overflow has
 *   occurred, no exception is thrown.
 *
 *   For all short values x, -x equals (~x) + 1.
 */
void Bytecodes::bc_sneg() {
  jshort_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SNEG");

  value = stack.pop_Short();
  stack.push_Short((jshort_t)-value);

  return;
}

/**
 * Boolean OR short
 *
 * Format:
 *   sor
 *
 * Forms:
 *   sor = 85 (0x55)
 *
 * Stack:
 *   ..., value1, value2 -> ..., result
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. The values are popped
 *   from the operand stack. A short result is calculated by taking the
 *   bitwise inclusive OR of value1 and value2. The result is pushed onto
 *   the operand stack.
 *
 */
void Bytecodes::bc_sor() {
  jshort_t value1, value2;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SOR");

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();

  stack.push_Short((jshort_t)(value1 | value2));

  return;
}

/**
 * Remainder short
 *
 * Format:
 *   srem
 *
 * Forms:
 *   srem = 73 (0x49)
 *
 * Stack:
 *   ..., value1, value2 -> ..., result
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. The values are popped
 *   from the operand stack. The short result is the value of the Java
 *   expression value1 - (value1 / value2) * value2. The result is pushed
 *   onto the operand stack.
 *
 *   The result of the srem instruction is such that (a/b)*b + (a%b) is
 *   equal to a. This identity holds even in the special case that the
 *   dividend is the negative short of largest possible magnitude for its
 *   type and the divisor is -1 (the remainder is 0). It follows from this
 *   rule that the result of the remainder operation can be negative only if
 *   the dividend is negative and can be positive only if the dividend is
 *   positive. Moreover, the magnitude of the result is always less than the
 *   magnitude of the divisor.
 *
 * Runtime Exception:
 *
 *   If the value of the divisor for a short remainder operator is 0, srem
 *   throws an ArithmeticException.
 */
void Bytecodes::bc_srem() {
  jshort_t value1;
  jshort_t value2;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SREM");

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();

  if (value2 == 0) { // division by 0
    throw Exceptions::ArithmeticException;
  } else if ((value1 == std::numeric_limits<jshort_t>::min()) &&
             (value2 == -1)) {
    stack.push_Short((jshort_t)(0));
  } else {
    stack.push_Short((jshort_t)(value1 % value2));
  }

  return;
}

/**
 * Shift left short
 *
 * Format:
 *   sshl
 *
 * Forms:
 *   sshl = 77 (0x4d)
 *
 * Stack:
 *   ..., value1, value2 -> ..., result
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. The values are popped
 *   from the operand stack. A short result is calculated by shifting value1
 *   left s bit positions, with sign extension, where s is the value of the
 *   low five bits of value2. The result is pushed onto the operand stack.
 *
 * Notes:
 *
 *   The resulting value is the ⌊value1/2^s⌋, where s is value2 & 0x1f. For
 *   nonnegative value1, this is equivalent (even if overflow occurs) to
 *   truncating short division by 2 to the power s. The shift distance
 *   actually used is always in the range 0 to 31, inclusive, as if value2
 *   were subjected to a bitwise logical AND with the mask value 0x1f.
 *
 *   The mask value of 0x1f allows shifting beyond the range of a 16-bit
 *   short value. It is used by this instruction, however, to ensure results
 *   equal to those generated by the Java instruction ishr.
 */
void Bytecodes::bc_sshl() {
  jshort_t value1, value2;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SSHL");

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();

  /**
   * C-language Standard:
   *
   * The result of E1 << E2 is E1 left-shifted E2 bit positions; vacated
   * bits are filled with zeros. If E1 has an unsigned type, the value of
   * the result is E1 × 2^E2 , reduced modulo one more than the maximum
   * value representable in the result type. If E1 has a signed type and
   * nonnegative value, and E1 × 2^E2 is representable in the result type,
   * then that is the resulting value; otherwise, the behavior is
   * undefined.
   *
   * [source: ISO/IEC 9899, §6.5.7 -- Bitwise shift operators]
   */

  stack.push_Short(value1 << (value2 & 0x1f));

  return;
}

/**
 *Arithmetic shift right short
 *
 *Format:
 *  sshr
 *
 *Forms:
 *  sshr = 79 (0x4f)
 *
 *Stack:
 *  ..., value1, value2 -> ..., result
 *
 *Description:
 *
 *  Both value1 and value2 must be of type short. The values are popped
 *  from the operand stack. A short result is calculated by shifting value1
 *  right by s bit positions, with sign extension, where s is the value of
 *  the low five bits of value2. The result is pushed onto the operand
 *  stack.
 *
 *Notes:
 *
 *  The resulting value is ⌊value1/2^s⌋, where s is value2 & 0x1f. For
 *  nonnegative value1, this is equivalent (even if overflow occurs) to
 *  truncating int division by 2 to the power s. The shift distance
 *  actually used is always in the range 0 to 31, inclusive, as if value2
 *  were subjected to a bitwise logical AND with the mask value 0x1f.
 *
 *  The mask value of 0x1f allows shifting beyond the range of a 16-bit
 *  short value. It is used by this instruction, however, to ensure results
 *  equal to those generated by the Java instruction ishr.
 */
void Bytecodes::bc_sshr() {
  jshort_t value1, value2;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SSHR");

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();

  /*
   * C-language Standard:
   *
   * The result of E1 >> E2 is E1 right-shifted E2 bit positions. If E1
   * has an unsigned type or if E1 has a signed type and a nonnegative
   * value, the value of the result is the integral part of the quotient
   * of E1/(2^E2). If E1 has a signed type and a negative value, the
   * resulting value is implementation-defined.
   *
   * [source: ISO/IEC 9899, §6.5.7 -- Bitwise shift operators]
   */

  // In ISO C, the operator >> is toolchain/platform dependent for
  // negative values
  if (value1 < 0) {
    stack.push_Short((jshort_t)(~((~value1) >> (value2 & 0x1f))));
  } else {
    stack.push_Short((jshort_t)(value1 >> (value2 & 0x1f)));
  }

  return;
}

/**
 * Subtract short
 *
 * Format:
 *   ssub
 *
 * Forms:
 *   ssub = 67 (0x43)
 *
 * Stack:
 *   ..., value1, value2 -> ..., result
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. The values are popped from
 *   the operand stack. The short result is value1 - value2. The result is
 *   pushed onto the operand stack.
 *
 *   For short subtraction, a - b produces the same result as a + (-b). For
 *   short values, subtraction from zeros is the same as negation.
 *
 *   Despite the fact that overflow or underflow may occur, in which case
 *   the result may have a different sign than the true mathematical result,
 *   execution of a ssub instruction never throws a runtime exception.
 */
void Bytecodes::bc_ssub() {
  jshort_t value1;
  jshort_t value2;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SSUB");

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();
  stack.push_Short((jshort_t)(value1 - value2));

  return;
}

/**
 * Logical shift right short
 *
 * Format:
 *   sushr
 *
 * Forms:
 *   sushr = 81 (0x51)
 *
 * Stack:
 *   ..., value1, value2 -> ..., result
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. The values are popped
 *   from the operand stack. A short result is calculated by sign-extending
 *   value1 to 32 bits[25] and shifting the result right by s bit positions,
 *   with zero extension, where s is the value of the low five bits of
 *   value2. The resulting value is then truncated to a 16-bit result. The
 *   result is pushed onto the operand stack.
 *
 *   25: Sign extension to 32 bits ensures that the result computed by this
 *   instruction will be exactly equal to that computed by the Java iushr
 *   instruction, regardless of the input values. In a JavaCard virtual
 *   machine the expression "0xffff >>> 0x01" yields 0xffff, where ">>>" is
 *   performed by the sushr instruction. The same result is rendered by a
 *   Java virtual machine.
 *
 * Notes:
 *
 *   If value1 is positive and s is value2 & 0x1f, the result is the same as
 *   that of value1 >> s; if value1 is negative, the result is equal to the
 *   value of the expression (value1 >> s) + (2 << ~s). The addition of the
 *   (2 << ~s) term cancels out the propagated sign bit. The shift distance
 *   actually used is always in the range 0 to 31, inclusive, as if value2
 *   were subjected to a bitwise logical AND with the mask value 0x1f.
 *
 *   The mask value of 0x1f allows shifting beyond the range of a 16-bit
 *   short value. It is used by this instruction, however, to ensure results
 *   equal to those generated by the Java instruction iushr.
 */
void Bytecodes::bc_sushr() {
  jshort_t value, s;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SUSHR");

  s = stack.pop_Short() & 0x1f;
  value = stack.pop_Short();

  /*
   * C-language Standard:
   *
   * The result of E1 >> E2 is E1 right-shifted E2 bit positions. If E1
   * has an unsigned type or if E1 has a signed type and a nonnegative
   * value, the value of the result is the integral part of the quotient
   * of E1/(2^E2). If E1 has a signed type and a negative value, the
   * resulting value is implementation-defined.
   *
   * [source: ISO/IEC 9899, §6.5.7 -- Bitwise shift operators]
   */

  if (value > 0) {
    stack.push_Short((jshort_t)(value >> s));
  } else {
    stack.push_Short((jshort_t)((value >> s) + (2 << ~s)));
  }

  return;
}

/**
 * Boolean XOR short
 *
 * Format:
 *   sxor
 *
 * Forms:
 *   sxor = 87 (0x57)
 *
 * Stack:
 *   ..., value1, value2 -> ..., result
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. The values are popped
 *   from the operand stack. A short result is calculated by taking the
 *   bitwise exclusive OR of value1 and value2. The result is pushed onto
 *   the operand stack.
 *
 */
void Bytecodes::bc_sxor() {
  jshort_t value1, value2;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SXOR");

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();

  stack.push_Short((jshort_t)(value1 ^ value2));

  return;
}

} // namespace jcvm
