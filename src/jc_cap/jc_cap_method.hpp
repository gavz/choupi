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

#ifndef _JC_CAP_METHOD_HPP
#define _JC_CAP_METHOD_HPP

#include "../jc_utils.hpp"
#include "../jcvm_types/jcvmarray.hpp"
#include "../types.hpp"

namespace jcvm {

struct __attribute__((__packed__)) jc_cap_exception_handler_info {
  uint16_t start_offset; /* Offset of where the try-statement starts */
#ifdef NVM_BIG_ENDIAN
  uint16_t stop_bit : 1; /* 0: there is/are another exception handler for the
                          * try-statement */
  uint16_t active_length : 15; /* Length in byte of the try-statement */
#else                          /* !NVM_BIG_ENDIAN */
  uint16_t active_length : 15; /* Length in byte of the try-statement */
  uint16_t stop_bit : 1;  /* 0: there is/are another exception handler for the
                           * try-statement */
#endif                         /* NVM_BIG_ENDIAN */
  uint16_t handler_offset;     /* Start offset of the catch/finally-statement */
  uint16_t catch_type_index;   /* !=0 => type of the exception to catch */
};

struct __attribute__((__packed__)) jc_cap_method_header_info {
#ifdef NVM_BIG_ENDIAN
  uint8_t flags : 4;     /* Method header flag */
  uint8_t max_stack : 4; /* Max operand stack word for the method */
#else                    /* !NVM_BIG_ENDIAN */
  uint8_t max_stack : 4;  /* Max operand stack word for the method */
  uint8_t flags : 4;      /* Method header flag */
#endif                   /* NVM_BIG_ENDIAN */

#ifdef NVM_BIG_ENDIAN
  uint8_t nargs : 4;      /* Method arguments word */
  uint8_t max_locals : 4; /* Number of method local variable word */
#else                     /* !NVM_BIG_ENDIAN */
  uint8_t max_locals : 4; /* Number of method local variable word */
  uint8_t nargs : 4;      /* Method arguments word */
#endif                    /* NVM_BIG_ENDIAN */
};

struct __attribute__((__packed__)) jc_cap_extended_method_header_info {
#ifdef NVM_BIG_ENDIAN
  uint8_t flags : 4;   /* Method header flags */
  uint8_t padding : 4; /* padding, must be equal to 0 */
#else                  /* !NVM_BIG_ENDIAN */
  uint8_t padding : 4;    /* padding, must be equal to 0 */
  uint8_t flags : 4;      /* Method header flags */
#endif                 /* NVM_BIG_ENDIAN */
  uint8_t max_stack;   /* Max operand stack word for the method */
  uint8_t nargs;       /* Method arguments word */
  uint8_t max_locals;  /* Number of method local variable word */
};

// #define JC_CAP_FLAGS_ACC_INTERFACE   (uint8_t) 0x8
// #define JC_CAP_FLAGS_ACC_SHAREABLE   (uint8_t) 0x4
// #define JC_CAP_FLAGS_ACC_REMOTE      (uint8_t) 0x2
// #define JC_CAP_FLAGS_ACC_DEFAULT     (uint8_t) 0x0

#define JC_CAP_METHOD_HEADER_FLAGS_ACC_EXTENDED (uint8_t)0x8
#define JC_CAP_METHOD_HEADER_FLAGS_ACC_ABSTRACT (uint8_t)0x4

struct __attribute__((__packed__)) jc_cap_method_info {
  struct jc_cap_method_header_info method_header; // Method header
  uint8_t bytecodes[];                            /* Method bytecodes */
};

struct __attribute__((__packed__)) jc_cap_extended_method_info {
  struct jc_cap_extended_method_header_info method_header; // Method header
  uint8_t bytecodes[]; /* Method bytecodes */
};

#define IS_EXTENDED_METHOD(method_info)                                        \
  (((struct jc_cap_method_info *)method_info)->method_header.flags &           \
   JC_CAP_METHOD_HEADER_FLAGS_ACC_EXTENDED)
#define IS_ABSTRACT_METHOD(method_info)                                        \
  (((struct jc_cap_method_info *)method_info)->method_header.flags &           \
   JC_CAP_METHOD_HEADER_FLAGS_ACC_ABSTRACT)

struct __attribute__((__packed__)) jc_cap_method_component {
  uint8_t tag;           /* Component tag: COMPONENT_Method (7) */
  uint16_t size;         /* Component size */
  uint8_t handler_count; /* Number of entries in the exception_handlers */
  uint8_t data[];
  // {
  //   jc_cap_exception_handler_info exception_handlers [/* handler_count */];
  //   uint8_t methods[];
  // }

  const JCVMArray<const jc_cap_exception_handler_info>
  exception_handlers() const noexcept {
    return JCVMArray<const jc_cap_exception_handler_info>(
        handler_count, (const jc_cap_exception_handler_info *)data);
  }

  const JCVMArray<const uint8_t> methods() const noexcept {
    return JCVMArray<const uint8_t>(
        (size - (handler_count * sizeof(jc_cap_exception_handler_info))),
        (uint8_t *)(data +
                    handler_count * sizeof(jc_cap_exception_handler_info)));
  }
};

} // namespace jcvm

#endif /* _JC_CAP_METHOD_HPP */
