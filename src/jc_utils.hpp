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

#ifndef _JC_UTILS_HPP
#define _JC_UTILS_HPP

#include "jc_config.h"
#include "types.hpp"

namespace jcvm {

#define MAX(a, b)                                                              \
  ({                                                                           \
    __typeof__(a) _a = (a);                                                    \
    __typeof__(b) _b = (b);                                                    \
    _a > _b ? _a : _b;                                                         \
  })

#define MIN(a, b)                                                              \
  ({                                                                           \
    __typeof__(a) _a = (a);                                                    \
    __typeof__(b) _b = (b);                                                    \
    _a > _b ? _b : _a;                                                         \
  })

#define LOW_NIBBLE(x) static_cast<uint8_t>(x & 0x0F)
#define HIGH_NIBBLE(x) LOW_NIBBLE(x >> 4)

#define LOW_BYTE_SHORT(x) static_cast<uint8_t>(x & 0x00FF)
#define HIGH_BYTE_SHORT(x) LOW_BYTE_SHORT(x >> 8)
#define BYTE_TO_SHORT(x) static_cast<uint16_t>(x & 0x00FF)
#define BYTE_TO_WORD BYTE_TO_SHORT

#ifdef JCVM_INT_SUPPORTED
#define INT_2_LSSHORTS(x) static_cast<uint16_t>(x & 0x0000FFFF)
#define INT_2_MSSHORTS(x) INT_2_LSSHORTS(x >> 16)
#endif /* JCVM_INT_SUPPORTED */

#define BYTES_TO_SHORT(x, y) static_cast<uint16_t>((x << 8) | (y & 0x00FF))

#ifdef JCVM_INT_SUPPORTED
#define SHORTS_TO_INT(x, y) static_cast<uint32_t>((x << 16) | (y & 0x0FFFF))
#define BYTES_TO_INT(w, x, y, z)                                               \
  ((BYTES_TO_SHORT(w, x) << 16) | (BYTES_TO_SHORT(y, z) & 0x0FFFF))
#endif /* JCVM_INT_SUPPORTED */

#define CLEAR_BYTE_MSB(x) (x & 0x7F)

// This piece of code was adapted from
// https://bytes.com/topic/c/answers/128237-portable-endianess
#if defined(NVM_BIG_ENDIAN) && !defined(NVM_LITTLE_ENDIAN)

#define HTONS(A) (A)
#define HTONI(A) (A)
#define NTOHS(A) (A)
#define NTOHI(A) (A)

#elif defined(NVM_LITTLE_ENDIAN) && !defined(NVM_BIG_ENDIAN)

#define HTONS(A)                                                               \
  static_cast<uint16_t>(((A & 0xff00) >> 8) | ((A & 0x00ff) << 8))

#define HTONI(A)                                                               \
  static_cast<uint32_t>(((A & 0xff000000) >> 24) | ((A & 0x00ff0000) >> 8) |   \
                        ((A & 0x0000ff00) << 8) | ((A & 0x000000ff) << 24))

#define NTOHS HTONS
#define NTOHI HTONI

#else

#error                                                                         \
    "Either NVM_BIG_ENDIAN or NVM_LITTLE_ENDIAN must be #defined, but not both."

#endif

} // namespace jcvm

#endif /* _JC_UTILS_HPP */
