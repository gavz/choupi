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
 * Load reference from local variable
 *
 * Format:
 *   aload
 *   index
 *
 * Forms:
 *   aload = 21 (0x15)
 *
 * Stack:
 *   ... -> ..., objectref
 *
 * Description:
 *
 *   The index is an unsigned byte that must be a valid index into the local
 *   variables of the current frame (§3.5 Frames). The local variable at
 *   index must contain a reference. The objectref in the local variable at
 *   index is pushed onto the operand stack.
 *
 * Notes:
 *
 *   The aload instruction cannot be used to load a value of type
 *   returnAddress from a local variable onto the operand stack. This
 *   asymmetry with the astore instruction is intentional.
 */
void Bytecodes::bc_aload() {
  uint8_t index;
  jref_t objectref;

  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("ALOAD 0x%02X", index);

  objectref = stack.readLocal_Reference(index);

  stack.push_Reference(objectref);

  return;
}

/**
 * Load short from local variable
 *
 * Format:
 *   sload
 *   index
 *
 * Forms:
 *   sload = 22 (0x16)
 *
 * Stack:
 *   ... -> ..., value
 *
 * Description:
 *
 *   The index is an unsigned byte that must be a valid index into the local
 *   variables of the current frame (§3.5 Frames). The local variable at
 *   index must contain a short. The value in the local variable at index is
 *   pushed onto the operand stack.
 */
void Bytecodes::bc_sload() {
  uint8_t index;
  jshort_t value;

  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("SLOAD 0x%02X", index);

  value = stack.readLocal_Short(index);

  stack.push_Short(value);

  return;
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Load int from local variable
 *
 * Format:
 *   iload
 *   index
 *
 * Forms:
 *   iload = 23 (0x17)
 *
 * Stack:
 *   ... -> ..., value1.word1, value1.word2
 *
 * Description:
 *
 *   The index is an unsigned byte. Both index and index + 1 must be valid
 *   indices into the local variables of the current frame (§3.5 Frames).
 *   The local variables at index and index + 1 together must contain an
 *   int. The value of the local variables at index and index + 1 is pushed
 *   onto the operand stack.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the iload
 *   instruction will not be available.
 */
void Bytecodes::bc_iload() {
  uint8_t index;
  jint_t value;

  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("ILOAD 0x%02X", index);

  value = stack.readLocal_Int(index);

  stack.push_Int(value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

/**
 * Load reference from local variable 0
 *
 * Format:
 *   aload_0
 *
 * Forms:
 *   aload_0 = 24 (0x18)
 *
 * Stack:
 *   ... -> ..., objectref
 *
 * Description:
 *
 *   The 0 must be a valid index into the local variables of the current
 *   frame (§3.5 Frames). The local variable at 0 must contain a reference.
 *   The objectref in the local variable at 0 is pushed onto the operand
 *   stack.
 *
 */
void Bytecodes::bc_aload_0() {
  jref_t objectref;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ALOAD_0");

  objectref = stack.readLocal_Reference(0);
  stack.push_Reference(objectref);

  return;
}

/**
 * Load reference from local variable 1
 *
 * Format:
 *   aload_1
 *
 * Forms:
 *   aload_1 = 25 (0x19)
 *
 * Stack:
 *   ... -> ..., objectref
 *
 * Description:
 *
 *   The 1 must be a valid index into the local variables of the current
 *   frame (§3.5 Frames). The local variable at 1 must contain a reference.
 *   The objectref in the local variable at 1 is pushed onto the operand
 *   stack.
 *
 */
void Bytecodes::bc_aload_1() {
  jref_t objectref;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ALOAD_1");

  objectref = stack.readLocal_Reference(1);
  stack.push_Reference(objectref);

  return;
}

/**
 * Load reference from local variable 2
 *
 * Format:
 *   aload_2
 *
 * Forms:
 *   aload_2 = 26 (0x1a)
 *
 * Stack:
 *   ... -> ..., objectref
 *
 * Description:
 *
 *   The 2 must be a valid index into the local variables of the current
 *   frame (§3.5 Frames). The local variable at 2 must contain a reference.
 *   The objectref in the local variable at 2 is pushed onto the operand
 *   stack.
 *
 */
void Bytecodes::bc_aload_2() {
  jref_t objectref;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ALOAD_2");

  objectref = stack.readLocal_Reference(2);
  stack.push_Reference(objectref);

  return;
}

/**
 * Load reference from local variable 3
 *
 * Format:
 *   aload_3
 *
 * Forms:
 *   aload_3 = 27 (0x1b)
 *
 * Stack:
 *   ... -> ..., objectref
 *
 * Description:
 *
 *   The 3 must be a valid index into the local variables of the current
 *   frame (§3.5 Frames). The local variable at 3 must contain a reference.
 *   The objectref in the local variable at 3 is pushed onto the operand
 *   stack.
 *
 */
void Bytecodes::bc_aload_3() {
  jref_t objectref;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ALOAD_3");

  objectref = stack.readLocal_Reference(3);

  stack.push_Reference(objectref);

  return;
}

/**
 * Load short from local variable 0
 *
 * Format:
 *   sload_0
 *
 * Forms:
 *   sload_0 = 28 (0x1c)
 *
 * Stack:
 *   ... -> ..., value
 *
 * Description:
 *
 *   The 0 must be a valid index into the local variables of the current
 *   frame (§3.5 Frames). The local variable at 0 must contain a short. The
 *   value in the local variable at is pushed onto the operand stack.
 *
 * Notes:
 *
 *   Each of the sload_0 instructions is the same as sload with an index
 *   of 0, except that the operand 0 is implicit.
 */
void Bytecodes::bc_sload_0() {
  jshort_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SLOAD_0");

  value = stack.readLocal_Short(0);
  stack.push_Short(value);

  return;
}

/**
 * Load short from local variable 1
 *
 * Format:
 *   sload_1
 *
 * Forms:
 *   sload_1 = 29 (0x1d)
 *
 * Stack:
 *   ... -> ..., value
 *
 * Description:
 *
 *   The 1 must be a valid index into the local variables of the current
 *   frame (§3.5 Frames). The local variable at 1 must contain a short. The
 *   value in the local variable at is pushed onto the operand stack.
 *
 * Notes:
 *
 *   Each of the sload_1 instructions is the same as sload with an index of
 *   1, except that the operand 1 is implicit.
 */
void Bytecodes::bc_sload_1() {
  jshort_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SLOAD_1");

  value = stack.readLocal_Short(1);
  stack.push_Short(value);

  return;
}

/**
 * Load short from local variable 2
 *
 * Format:
 *   sload_2
 *
 * Forms:
 *   sload_2 = 30 (0x1e)
 *
 * Stack:
 *   ... -> ..., value
 *
 * Description:
 *
 *   The 2 must be a valid index into the local variables of the current
 *   frame (§3.5 Frames). The local variable at 2 must contain a short. The
 *   value in the local variable at is pushed onto the operand stack.
 *
 * Notes:
 *
 *   Each of the sload_2 instructions is the same as sload with an index of
 *   2, except that the operand 2 is implicit.
 */
void Bytecodes::bc_sload_2() {
  jshort_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SLOAD_2");

  value = stack.readLocal_Short(2);
  stack.push_Short(value);

  return;
}

/**
 * Load short from local variable 3
 *
 * Format:
 *   sload_3
 *
 * Forms:
 *   sload_3 = 31 (0x1f)
 *
 * Stack:
 *   ... -> ..., value
 *
 * Description:
 *
 *   The 3 must be a valid index into the local variables of the current
 *   frame (§3.5 Frames). The local variable at 3 must contain a short. The
 *   value in the local variable at is pushed onto the operand stack.
 *
 * Notes:
 *
 *   Each of the sload_3 instructions is the same as sload with an index of
 *   3, except that the operand 3 is implicit.
 */
void Bytecodes::bc_sload_3() {
  jshort_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SLOAD_3");

  value = stack.readLocal_Short(3);
  stack.push_Short(value);

  return;
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Load int from local variable 0
 *
 * Format:
 *   iload_0
 *
 * Forms:
 *   iload_0 = 32 (0x20)
 *
 * Stack:
 *   ... -> ..., value1.word1, value1.word2
 *
 * Description:
 *
 *   Both 0 and 1 must be a valid indices into the local variables of the
 *   current frame (§3.5 Frames). The local variables at 0 and 1 together
 *   must contain an int. The value of the local variables at 0 and 1 is
 *   pushed onto the operand stack.
 *
 * Notes:
 *
 *   Each of the iload_0 instructions is the same as iload with an index of
 *   0, except that the operand 0 is implicit.
 *
 *   If a virtual machine does not support the int data type, the iload_0
 *   instruction will not be available.
 */
void Bytecodes::bc_iload_0() {
  jint_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ILOAD_0");

  value = stack.readLocal_Int(0);
  stack.push_Int(value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED

/**
 * Load int from local variable 1
 *
 * Format:
 *   iload_1
 *
 * Forms:
 *   iload_1 = 33 (0x21)
 *
 * Stack:
 *   ... -> ..., value1.word1, value1.word2
 *
 * Description:
 *
 *   Both 1 and 2 must be a valid indices into the local variables of the
 *   current frame (§3.5 Frames). The local variables at 1 and 2 together
 *   must contain an int. The value of the local variables at 1 and 2 is
 *   pushed onto the operand stack.
 *
 * Notes:
 *
 *   Each of the iload_1 instructions is the same as iload with an index of
 *   1, except that the operand 1 is implicit.
 *
 *   If a virtual machine does not support the int data type, the iload_1
 *   instruction will not be available.
 */
void Bytecodes::bc_iload_1() {
  jint_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ILOAD_1");

  value = stack.readLocal_Int(1);
  stack.push_Int(value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Load int from local variable 2
 *
 * Format:
 *   iload_2
 *
 * Forms:
 *   iload_2 = 34 (0x22)
 *
 * Stack:
 *   ... -> ..., value1.word1, value1.word2
 *
 * Description:
 *
 *   Both 2 and 3 must be a valid indices into the local variables of the
 *   current frame (§3.5 Frames). The local variables at 2 and 3 together
 *   must contain an int. The value of the local variables at 2 and 3 is
 *   pushed onto the operand stack.
 *
 * Notes:
 *
 *   Each of the iload_2 instructions is the same as iload with an index of
 *   2, except that the operand 2 is implicit.
 *
 *   If a virtual machine does not support the int data type, the iload_2
 *   instruction will not be available.
 */
void Bytecodes::bc_iload_2() {
  jint_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ILOAD_2");

  value = stack.readLocal_Int(2);
  stack.push_Int(value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Load int from local variable 3
 *
 * Format:
 *   iload_3
 *
 * Forms:
 *   iload_3 = 35 (0x23)
 *
 * Stack:
 *   ... -> ..., value1.word1, value1.word2
 *
 * Description:
 *
 *   Both 3 and 4 must be a valid indices into the local variables of the
 *   current frame (§3.5 Frames). The local variables at 3 and 4 together
 *   must contain an int. The value of the local variables at 3 and 4 is
 *   pushed onto the operand stack.
 *
 * Notes:
 *
 *   Each of the iload_3 instructions is the same as iload with an index of
 *   3, except that the operand 3 is implicit.
 *
 *   If a virtual machine does not support the int data type, the iload_3
 *   instruction will not be available.
 */
void Bytecodes::bc_iload_3() {
  jint_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ILOAD_3");

  value = stack.readLocal_Int(3);
  stack.push_Int(value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */
} // namespace jcvm
