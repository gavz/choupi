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
 * Store reference into local variable
 *
 * Format:
 *   astore
 *   index
 *
 * Forms:
 *   astore = 40 (0x28)
 *
 * Stack:
 *   ..., objectref -> ...
 *
 * Description:
 *
 *   The index is an unsigned byte that must be a valid index into the local
 *   variables of the current frame (§3.5 Frames). The objectref on the top
 *   of the operand stack must be of type returnAddress or of type
 *   reference. The objectref is popped from the operand stack, and the
 *   value of the local variable at index is set to objectref.
 *
 * Notes:
 *
 *   The astore instruction is used with an objectref of type returnAddress
 *   when implementing Java's finally keyword. The aload instruction cannot
 *   be used to load a value of type returnAddress from a local variable
 *   onto the operand stack. This asymmetry with the astore instruction is
 *   intentional.
 */
void Bytecodes::bc_astore() {
  uint8_t index;
  jref_t objectref;

  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("ASTORE 0x%02X", index);

  objectref = stack.pop_Reference();

  stack.writeLocal_Reference(index, objectref);

  return;
}

/**
 * Store short into local variable
 *
 * Format:
 *   sstore
 *   index
 *
 * Forms:
 *   sstore = 41 (0x29)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The index is an unsigned byte that must be a valid index into the local
 *   variables of the current frame (§3.5 Frames). The value on top of the
 *   operand stack must be of type short. It is popped from the operand
 *   stack, and the value of the local variable at index is set to value.
 */
void Bytecodes::bc_sstore() {
  uint8_t index;
  jshort_t value;

  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("SSTORE 0x%02X", index);

  value = stack.pop_Short();

  stack.writeLocal_Short(index, value);

  return;
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Store int into local variable
 *
 * Format:
 *   istore
 *   index
 *
 * Forms:
 *   istore = 42 (0x2a)
 *
 * Stack:
 *   ..., value.word1, value.word2 -> ...
 *
 * Description:
 *
 *   The index is an unsigned byte. Both index and index + 1 must be a valid
 *   index into the local variables of the current frame (§3.5 Frames). The
 *   value on top of the operand stack must be of type int. It is popped
 *   from the operand stack, and the local variables at index and index + 1
 *   are set to value.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the istore
 *   instruction will not be available.
 */
void Bytecodes::bc_istore() {
  uint8_t index;
  jint_t value;

  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("ISTORE 0x%02X", index);

  value = stack.pop_Int();

  stack.writeLocal_Int(index, value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

/**
 * Store reference into local variable 0
 *
 * Format:
 *   astore_0
 *
 * Forms:
 *   astore_0 = 43 (0x2b)
 *
 * Stack:
 *   ..., objectref -> ...
 *
 * Description:
 *
 *   The 0 must be a valid index into the local variables of the current
 *   frame (§3.5 Frames). The objectref on the top of the operand stack must
 *   be of type returnAddress or of type reference. It is popped from the
 *   operand stack, and the value of the local variable at 0 is set to
 *   objectref.
 *
 * Notes:
 *
 *   An astore_0 instruction is used with an objectref of type returnAddress
 *   when implementing Java's finally keyword. An aload_0 instruction cannot
 *   be used to load a value of type returnAddress from a local variable
 *   onto the operand stack. This asymmetry with the corresponding astore_0
 *   instruction is intentional.
 *
 *   Each of the astore_0 instructions is the same as astore with an index
 *   of 0, except that the operand 0 is implicit.
 */
void Bytecodes::bc_astore_0() {
  jref_t objectref;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ASTORE_0");

  // TODO: The popped reference may have the type returnAddress ...
  objectref = stack.pop_Reference();
  stack.writeLocal_Reference(0, objectref);

  return;
}

/**
 * Store reference into local variable 1
 *
 * Format:
 *   astore_1
 *
 * Forms:
 *   astore_1 = 44 (0x2c)
 *
 * Stack:
 *   ..., objectref -> ...
 *
 * Description:
 *
 *   The 1 must be a valid index into the local variables of the current
 *   frame (§3.5 Frames). The objectref on the top of the operand stack must
 *   be of type returnAddress or of type reference. It is popped from the
 *   operand stack, and the value of the local variable at 1 is set to
 *   objectref.
 *
 * Notes:
 *
 *   An astore_1 instruction is used with an objectref of type returnAddress
 *   when implementing Java's finally keyword. An aload_1 instruction cannot
 *   be used to load a value of type returnAddress from a local variable
 *   onto the operand stack. This asymmetry with the corresponding astore_1
 *   instruction is intentional.
 *
 *   Each of the astore_1 instructions is the same as astore with an index
 *   of 1, except that the operand 1 is implicit.
 */
void Bytecodes::bc_astore_1() {
  jref_t objectref;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ASTORE_1");

  objectref = stack.pop_Reference();
  stack.writeLocal_Reference(1, objectref);

  return;
}

/**
 * Store reference into local variable 2
 *
 * Format:
 *   astore_2
 *
 * Forms:
 *   astore_2 = 45 (0x2d)
 *
 * Stack:
 *   ..., objectref -> ...
 *
 * Description:
 *
 *   The 2 must be a valid index into the local variables of the current
 *   frame (§3.5 Frames). The objectref on the top of the operand stack must
 *   be of type returnAddress or of type reference. It is popped from the
 *   operand stack, and the value of the local variable at 2 is set to
 *   objectref.
 *
 * Notes:
 *
 *   An astore_2 instruction is used with an objectref of type returnAddress
 *   when implementing Java's finally keyword. An aload_2 instruction cannot
 *   be used to load a value of type returnAddress from a local variable
 *   onto the operand stack. This asymmetry with the corresponding astore_2
 *   instruction is intentional.
 *
 *   Each of the astore_2 instructions is the same as astore with an index
 *   of 2, except that the operand 2 is implicit.
 */
void Bytecodes::bc_astore_2() {
  jref_t objectref;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ASTORE_2");

  objectref = stack.pop_Reference();
  stack.writeLocal_Reference(2, objectref);

  return;
}

/**
 * Store reference into local variable 3
 *
 * Format:
 *   astore_3
 *
 * Forms:
 *   astore_3 = 46 (0x2e)
 *
 * Stack:
 *   ..., objectref -> ...
 *
 * Description:
 *
 *   The 3 must be a valid index into the local variables of the current
 *   frame (§3.5 Frames). The objectref on the top of the operand stack must
 *   be of type returnAddress or of type reference. It is popped from the
 *   operand stack, and the value of the local variable at 3 is set to
 *   objectref.
 *
 * Notes:
 *
 *   An astore_3 instruction is used with an objectref of type returnAddress
 *   when implementing Java's finally keyword. An aload_3 instruction cannot
 *   be used to load a value of type returnAddress from a local variable
 *   onto the operand stack. This asymmetry with the corresponding astore_3
 *   instruction is intentional.
 *
 *   Each of the astore_3 instructions is the same as astore with an index
 *   of 3, except that the operand 0 is implicit.
 */
void Bytecodes::bc_astore_3() {
  jref_t objectref;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ASTORE_3");

  // TODO: The reference popped may have the type returnAddress ...
  objectref = stack.pop_Reference();
  stack.writeLocal_Reference(3, objectref);

  return;
}

/**
 * Store short into local variable 0
 *
 * Format:
 *   sstore_0
 *
 * Forms:
 *   sstore_0 = 47 (0x2f)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The 0 must be a valid index into the local variables of the current
 *   frame (§3.5 Frames). The value on top of the operand stack must be of
 *   type short. It is popped from the operand stack, and the value of the
 *   local variable at 0 is set to value.
 */
void Bytecodes::bc_sstore_0() {
  jshort_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SSTORE_0");

  value = stack.pop_Short();
  stack.writeLocal_Short(0, value);

  return;
}

/**
 * Store short into local variable 1
 *
 * Format:
 *   sstore_1
 *
 * Forms:
 *   sstore_1 = 48 (0x30)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The 1 must be a valid index into the local variables of the current
 *   frame (§3.5 Frames). The value on top of the operand stack must be of
 *   type short. It is popped from the operand stack, and the value of the
 *   local variable at 1 is set to value.
 */
void Bytecodes::bc_sstore_1() {
  jshort_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SSTORE_1");

  value = stack.pop_Short();
  stack.writeLocal_Short(1, value);

  return;
}

/**
 * Store short into local variable 2
 *
 * Format:
 *   sstore_2
 *
 * Forms:
 *   sstore_2 = 49 (0x31)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The 2 must be a valid index into the local variables of the current
 *   frame (§3.5 Frames). The value on top of the operand stack must be of
 *   type short. It is popped from the operand stack, and the value of the
 *   local variable at 2 is set to value.
 */
void Bytecodes::bc_sstore_2() {
  jshort_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SSTORE_2");

  value = stack.pop_Short();
  stack.writeLocal_Short(2, value);

  return;
}

/**
 * Store short into local variable 3
 *
 * Format:
 *   sstore_3
 *
 * Forms:
 *   sstore_3 = 50 (0x32)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The 1 must be a valid index into the local variables of the current
 *   frame (§3.5 Frames). The value on top of the operand stack must be of
 *   type short. It is popped from the operand stack, and the value of the
 *   local variable at 3 is set to value.
 */
void Bytecodes::bc_sstore_3() {
  jshort_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SSTORE_3");

  value = stack.pop_Short();
  stack.writeLocal_Short(3, value);

  return;
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Store int into local variable 0
 *
 * Format:
 *   istore_0
 *
 * Forms:
 *   istore_0 = 51 (0x33)
 *
 * Stack:
 *   ..., value.word1, value.word2 -> ...
 *
 * Description:
 *
 *   Both 0 and 1 must be a valid indices into the local variables of the
 *   current frame (§3.5 Frames). The value on top of the operand stack must
 *   be of type int. It is popped from the operand stack, and the local
 *   variables at index and index + 1 are set to value.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the istore_0
 *   instruction will not be available.
 */
void Bytecodes::bc_istore_0() {
  jint_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ISTORE_0");

  value = stack.pop_Int();
  stack.writeLocal_Int(0, value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Store int into local variable 1
 *
 * Format:
 *   istore_1
 *
 * Forms:
 *   istore_1 = 52 (0x34)
 *
 * Stack:
 *   ..., value.word1, value.word2 -> ...
 *
 * Description:
 *
 *   Both 1 and 2 must be a valid indices into the local variables of the
 *   current frame (§3.5 Frames). The value on top of the operand stack must
 *   be of type int. It is popped from the operand stack, and the local
 *   variables at index and index + 1 are set to value.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the istore_0
 *   instruction will not be available.
 */
void Bytecodes::bc_istore_1() {
  jint_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ISTORE_1");

  value = stack.pop_Int();
  stack.writeLocal_Int(1, value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Store int into local variable 2
 *
 * Format:
 *   istore_2
 *
 * Forms:
 *   istore_2 = 53 (0x35)
 *
 * Stack:
 *   ..., value.word1, value.word2 -> ...
 *
 * Description:
 *
 *   Both 2 and 3 must be a valid indices into the local variables of the
 *   current frame (§3.5 Frames). The value on top of the operand stack must
 *   be of type int. It is popped from the operand stack, and the local
 *   variables at index and index + 1 are set to value.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the istore_2
 *   instruction will not be available.
 */
void Bytecodes::bc_istore_2() {
  jint_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ISTORE_2");

  value = stack.pop_Int();
  stack.writeLocal_Int(2, value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

#ifdef JCVM_INT_SUPPORTED
/**
 * Store int into local variable 3
 *
 * Format:
 *   istore_3
 *
 * Forms:
 *   istore_3 = 54 (0x36)
 *
 * Stack:
 *   ..., value.word1, value.word2 -> ...
 *
 * Description:
 *
 *   Both 3 and 4 must be a valid indices into the local variables of the
 *   current frame (§3.5 Frames). The value on top of the operand stack must
 *   be of type int. It is popped from the operand stack, and the local
 *   variables at index and index + 1 are set to value.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the istore_3
 *   instruction will not be available.
 */
void Bytecodes::bc_istore_3() {
  jint_t value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ISTORE_3");

  value = stack.pop_Int();
  stack.writeLocal_Int(3, value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */
} // namespace jcvm
