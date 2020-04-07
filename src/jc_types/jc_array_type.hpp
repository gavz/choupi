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

#ifndef _JC_ARRAY_TYPE_HPP
#define _JC_ARRAY_TYPE_HPP

#include "../jc_config.h"
#include "../types.hpp"

namespace jcvm {

enum jc_array_type : uint8_t {
  // JAVA_ARRAY_UNINITIALIZED = 0x00,

  // JAVA_ARRAY_NOT_ARRAY = 0xFF,

  JAVA_ARRAY_T_BOOLEAN = 0x10,
  JAVA_ARRAY_T_BYTE = 0x11,
  JAVA_ARRAY_T_SHORT = 0x12,

#ifdef JCVM_INT_SUPPORTED
  JAVA_ARRAY_T_INT = 0x13,
#endif /* JCVM_INT_SUPPORTED */

  JAVA_ARRAY_T_REFERENCE = 0x14,
};

} // namespace jcvm
#endif /* _JC_ARRAY_TYPE_HPP */
