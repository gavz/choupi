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

#ifndef _TYPES_HPP
#define _TYPES_HPP

#include "jc_config.h"

/*
 * XXX: For Java Card language:
 *   - A  byte  is a signed  8-bit type.
 *   - A  short is a signed 16-bit type.
 *   - An int   is a signed 32-bit type.
 *   - The reference type is not define: implementation dependent.
 *   - The returnadress type is a Numerical type (but without arithmetic).
 */
#include <cstdint>

namespace jcvm {

/// a Java Card byte type
typedef int8_t jbyte_t;
/// a Java Card short type
typedef int16_t jshort_t;
/// a Java Card generic word type
typedef jshort_t jword_t;
#ifdef JCVM_INT_SUPPORTED
/// a Java Card int type
typedef int32_t jint_t;
#endif /* JCVM_INT_SUPPORTED */

/// a Java Card Boolean type
enum jbool_t : uint8_t {
  FALSE = static_cast<jbyte_t>(0),
  TRUE = static_cast<jbyte_t>(1),
};

inline jbool_t byte2bool(const jbyte_t value) noexcept {
  switch (value) {
  case FALSE:
    return FALSE;

  case TRUE:
  default:
    return TRUE;
  }
};

/// A Java Card Return address
typedef uint16_t jreturnaddress_t;

/// The constant pool component
typedef uint16_t jc_cp_offset_t;

/// Java Card package ID type
typedef uint8_t jpackage_ID_t;

/// Java Card applet ID type
typedef uint8_t japplet_ID_t;

/// Java Card class index type
typedef uint16_t jclass_index_t;

#define JTYPE_SHORT (uint8_t)0x0
#define JTYPE_INT (uint8_t)0x7           // 0b0111
#define JTYPE_INT_LOW_PART (uint8_t)0x5  // 0b0101
#define JTYPE_INT_HIGH_PART (uint8_t)0x6 // 0b0110
#define JTYPE_OBJECT (uint8_t)0x8        // 0b1000

} // namespace jcvm

#endif /* _TYPES_HPP */
