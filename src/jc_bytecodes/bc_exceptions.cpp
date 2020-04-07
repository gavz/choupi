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
 * Throw exception or error
 *
 * Format:
 *   athrow
 *
 * Forms:
 *   athrow = 147 (0x93)
 *
 * Stack:
 *   ..., objectref -> objectref
 *
 * Description:
 *
 *   The objectref must be of type reference and must refer to an object
 *   that is an instance of class Throwable or of a subclass of Throwable.
 *   It is popped from the operand stack. The objectref is then thrown by
 *   searching the current frame (§3.5 Frames) for the most recent catch
 *   clause that catches the class of objectref or one of its superclasses.
 *
 *   If a catch clause is found, it contains the location of the code
 *   intended to handle this exception. The pc register is reset to that
 *   location, the operand stack of the current frame is cleared, objectref
 *   is pushed back onto the operand stack, and execution continues. If no
 *   appropriate clause is found in the current frame, that frame is popped,
 *   the frame of its invoker is reinstated, and the objectref is rethrown.
 *
 *   If no catch clause is found that handles this exception, the virtual
 *   machine exits.
 *
 * Runtime Exception:
 *
 *   If objectref is null, athrow throws a NullPointerException instead of
 *   objectref.
 *
 * Notes:
 *
 *   In some circumstances, the athrow instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_athrow() {
  jref_t objectref;
  Stack &stack = this->context.getStack();

  TRACE_JCVM_DEBUG("ATHROW");

  objectref = stack.pop_Reference();
  this->doThrow(objectref);

  return;
}

/**
 * Throwing an exception
 *
 */
void Bytecodes::doThrow(jref_t objectref) {
  // TODO: Implementing this instruction
  throw Exceptions::NotYetImplemented;
}

} // namespace jcvm
