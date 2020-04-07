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

#ifndef _JC_FIELD_HPP
#define _JC_FIELD_HPP

#include "../types.hpp"

namespace jcvm {

enum FieldType : uint8_t {
  FIELD_TYPE_BYTE = (uint8_t)0,
  FIELD_TYPE_BOOLEAN = (uint8_t)1,
  FIELD_TYPE_SHORT = (uint8_t)2,
#ifdef JCVM_INT_SUPPORTED
  FIELD_TYPE_INT = (uint8_t)3,
#endif /* JCVM_INT_SUPPORTED */
  FIELD_TYPE_OBJECT = (uint8_t)4,

  FIELD_TYPE_ARRAY_BYTE = (uint8_t)((1 << 7) | FIELD_TYPE_BYTE),
  FIELD_TYPE_ARRAY_BOOLEAN = (uint8_t)((1 << 7) | FIELD_TYPE_BOOLEAN),
  FIELD_TYPE_ARRAY_SHORT = (uint8_t)((1 << 7) | FIELD_TYPE_SHORT),
#ifdef JCVM_INT_SUPPORTED
  FIELD_TYPE_ARRAY_INT = (uint8_t)((1 << 7) | FIELD_TYPE_INT),
#endif /* JCVM_INT_SUPPORTED */
  FIELD_TYPE_ARRAY_OBJECT = (uint8_t)((1 << 7) | FIELD_TYPE_OBJECT),

  FIELD_TYPE_TRANSIENT_ARRAY_BYTE = (uint8_t)((1 << 6) | FIELD_TYPE_ARRAY_BYTE),
  FIELD_TYPE_TRANSIENT_ARRAY_BOOLEAN =
      (uint8_t)((1 << 6) | FIELD_TYPE_ARRAY_BOOLEAN),
  FIELD_TYPE_TRANSIENT_ARRAY_SHORT =
      (uint8_t)((1 << 6) | FIELD_TYPE_ARRAY_SHORT),
#ifdef JCVM_INT_SUPPORTED
  FIELD_TYPE_TRANSIENT_ARRAY_INT = (uint8_t)((1 << 6) | FIELD_TYPE_ARRAY_INT),
#endif /* JCVM_INT_SUPPORTED */
  FIELD_TYPE_TRANSIENT_ARRAY_OBJECT =
      (uint8_t)((1 << 6) | FIELD_TYPE_ARRAY_OBJECT),

  FIELD_TYPE_UNINITIALIZED = (uint8_t)(-1),

}; // namespace jcvm

struct jc_field_t {
  FieldType type;
  jword_t value;
};

} // namespace jcvm

#endif /* _JC_FIELD_HPP */
