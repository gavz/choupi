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

#ifndef _JC_STATIC_HPP
#define _JC_STATIC_HPP

#include "../jc_config.h"
#include "../jc_types/jref_t.hpp"
#include "../types.hpp"
#include "jc_component.hpp"

namespace jcvm {

class Heap; // Forward declaration of Heap

class Static_Handler : public Component_Handler {
public:
  /// Default constructor
  Static_Handler(Package package) noexcept : Component_Handler(package){};

  /// Read static byte value.
  jbyte_t getPersistentByte(const uint16_t index) const;
  /// Read static short value.
  jshort_t getPersistentShort(const uint16_t index) const;
#ifdef JCVM_INT_SUPPORTED
  /// Read static integer value.
  jint_t getPersistentInt(const uint16_t index) const;
#endif /* JCVM_INT_SUPPORTED */
  /// Read static serialized instance or array.
  jref_t getPersistentRef(const uint16_t index, Heap &heap) const;

  /// Set static byte value.
  void setPersistentByte(const uint16_t index, const jbyte_t value);
  /// Set static short value.
  void setPersistentShort(const uint16_t index, const jshort_t value);
#ifdef JCVM_INT_SUPPORTED
  /// Set static integer value.
  void setPersistentInt(const uint16_t index, const jint_t value);
#endif /* JCVM_INT_SUPPORTED */
};

} // namespace jcvm

#endif /* _JC_STATIC_HPP */
