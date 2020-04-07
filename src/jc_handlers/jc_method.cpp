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

#include "jc_method.hpp"
#include "../heap.hpp"
#include "../stack.hpp"

namespace jcvm {

/**
 * Get method from offset.
 *
 * @param[method_offset] method offset to resolve.
 *
 * @return method from method_offset with the type struct jc_cap_method_info or
 * struct jc_cap_extended_method_info
 */
const uint8_t *Method_Handler::getMethodFromOffset(const uint16_t method_offset)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
    noexcept
#endif
{
  auto cap = this->package.getCap();

#ifdef JCVM_DYNAMIC_CHECKS_CAP

  if (cap.getMethod() == nullptr) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_DYNAMIC_CHECKS_CAP */

  const JCVMArray<const uint8_t> methods = cap.getMethod()->methods();

  // NOTE: The method offset starts from 1.
  return &(methods.at(method_offset - 1));
}

/**
 * Calling a method.
 *
 * @param[method_to_call] pointer to the method to call.
 * @param[isStaticMethod] is a static method?
 */
void Method_Handler::callMethod(const uint8_t *const method_to_call,
                                const jbool_t isStaticMethod)
#if !defined(JCVM_DYNAMIC_CHECKS_CAP) && !defined(JCVM_FIREWALL_CHECKS)
    noexcept
#endif
{
  uint8_t nargs, max_stack, max_locals;
  const uint8_t *new_pc;

#ifdef JCVM_DYNAMIC_CHECKS_CAP

  if (IS_ABSTRACT_METHOD(method_to_call)) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_DYNAMIC_CHECKS_CAP */

  if (IS_EXTENDED_METHOD(method_to_call)) {
    auto method_to_run =
        reinterpret_cast<const jc_cap_extended_method_info *>(method_to_call);

    max_stack = method_to_run->method_header.max_stack;
    nargs = method_to_run->method_header.nargs;
    max_locals = method_to_run->method_header.max_locals;
    new_pc = method_to_run->bytecodes;
  } else { // normal method header
    auto method_to_run =
        reinterpret_cast<const jc_cap_method_info *>(method_to_call);

    max_stack = LOW_NIBBLE(method_to_run->method_header.max_stack);
    nargs = LOW_NIBBLE(method_to_run->method_header.nargs);
    max_locals = LOW_NIBBLE(method_to_run->method_header.max_locals);
    new_pc = method_to_run->bytecodes;
  }

#ifdef JCVM_FIREWALL_CHECKS

  if ((isStaticMethod == FALSE) && (nargs == 0)) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_FIREWALL_CHECKS */

  // pushing the new frame
  this->context.getStack().push_Frame(nargs, max_locals, max_stack, new_pc);

  //  and updating executed package ID.

  this->context.changePackageID(this->package.getPackageID());

  return;
}

/**
 * Call a virtual method
 *
 * @param[method_offset] offset in the method component where the method to
 *                       executed is located.
 */
void Method_Handler::callVirtualMethod(const uint16_t method_offset) {
  const uint8_t *method_to_call = this->getMethodFromOffset(method_offset);
  this->callMethod(method_to_call);
  return;
}

/**
 * Call a static method
 *
 * @param[method_offset] offset in the method component where the method to
 *                       executed is located.
 */
void Method_Handler::callStaticMethod(const uint16_t method_offset) {
  const uint8_t *method_to_call = this->getMethodFromOffset(method_offset);
  this->callMethod(method_to_call, TRUE);
  return;
}

} // namespace jcvm
