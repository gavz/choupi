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
#include "../stack.hpp"
#include "bytecodes.hpp"

namespace jcvm {

/**
 * Return reference from method
 *
 * Format:
 *   areturn
 *
 * Forms:
 *   areturn = 119 (0x77)
 *
 * Stack:
 *   ..., objectref -> [empty]
 *
 * Description:
 *
 *   The objectref must be of type reference. The objectref is popped from
 *   the operand stack of the current frame (§3.5 Frames) and pushed onto the
 *   operand stack of the frame of the invoker. Any other values on the
 *   operand stack of the current method are discarded.
 *
 *   The virtual machine then reinstates the frame of the invoker and
 *   returns control to the invoker.
 *
 */
void Bytecodes::bc_areturn() {
  jref_t returned_value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ARETURN");

  returned_value = stack.pop_Reference();

  stack.pop_Frame();
  context.backToPreviousPackageID();

  stack.push_Reference(returned_value);

  return;
}

/**
 * Return short from method
 *
 * Format:
 *   sreturn
 *
 * Forms:
 *   sreturn = 120 (0x78)
 *
 * Stack:
 *   ..., value -> [empty]
 *
 * Description:
 *
 *   The value must be of type short. It is popped from the operand stack of
 *   the current frame (§3.5 Frames) and pushed onto the operand stack of
 *   the frame of the invoker. Any other values on the operand stack of the
 *   current method are discarded.
 *
 *   The virtual machine then reinstates the frame of the invoker and
 *   returns control to the invoker.
 *
 */
void Bytecodes::bc_sreturn() {
  jshort_t returned_value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("SRETURN");

  returned_value = stack.pop_Short();

  stack.pop_Frame();
  context.backToPreviousPackageID();

  stack.push_Short(returned_value);

  return;
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Return int from method
 *
 * Format:
 *   ireturn
 *
 * Forms:
 *   ireturn = 121 (0x79)
 *
 * Stack:
 *   ..., value.word1, value.word2 -> [empty]
 *
 * Description:
 *
 *   The value must be of type int. It is popped from the operand stack of
 *   the current frame (§3.5 Frames) and pushed onto the operand stack of
 *   the frame of the invoker. Any other values on the operand stack of the
 *   current method are discarded.
 *
 *   The virtual machine then reinstates the frame of the invoker and
 *   returns control to the invoker.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the ireturn
 *   instruction will not be available.
 *
 */
void Bytecodes::bc_ireturn() {
  jint_t returned_value;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("IRETURN");

  returned_value = stack.pop_Int();

  stack.pop_Frame();
  context.backToPreviousPackageID();

  stack.push_Int(returned_value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

/**
 * Return void from method
 *
 * Format:
 *   return
 *
 * Forms:
 *   return = 122 (0x7a)
 *
 * Stack:
 *   ... -> [empty]
 *
 * Description:
 *
 *   Any values on the operand stack of the current method are discarded.
 *   The virtual machine then reinstates the frame of the invoker and
 *   returns control to the invoker.
 *
 */
void Bytecodes::bc_return() {
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("RETURN");

  stack.pop_Frame();
  context.backToPreviousPackageID();

  return;
}
} // namespace jcvm
