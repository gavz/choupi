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

#ifndef _JC_METHOD_HPP
#define _JC_METHOD_HPP

#include "../context.hpp"
#include "../jc_cap/jc_cap_method.hpp"
#include "../jc_utils.hpp"
#include "../types.hpp"
#include "jc_cap.hpp"
#include "jc_component.hpp"

namespace jcvm {

class Method_Handler : public Component_Handler {
private:
  Context &context;

  /// Get method from offset.
  const uint8_t *getMethodFromOffset(const uint16_t method_offset)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;

  void callMethod(const uint8_t *const method_to_call,
                  const jbool_t isStaticMethod = FALSE)
#if !defined(JCVM_DYNAMIC_CHECKS_CAP) && !defined(JCVM_FIREWALL_CHECKS)
      noexcept
#endif
      ;

public:
  /// Default constructor
  Method_Handler(Context &context) noexcept
      : Component_Handler(context.getCurrentPackage()), context(context){};

  /// Call a virtual method
  void callVirtualMethod(const uint16_t method_offset);

  /// Call a static method
  void callStaticMethod(const uint16_t method_offset);
};

} // namespace jcvm
#endif /* _JC_METHOD_HPP */
