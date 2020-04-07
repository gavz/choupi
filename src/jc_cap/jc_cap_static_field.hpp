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

#ifndef _JC_CAP_STATIC_FIELD_HPP
#define _JC_CAP_STATIC_FIELD_HPP

#include "../jc_config.h"
#include "../jc_utils.hpp"
#include "../jcvm_types/jcvmarray.hpp"
#include "../types.hpp"

namespace jcvm {

struct __attribute__((__packed__)) jc_cap_array_init_info {
  /// Type of primitive array
  uint8_t type;
  /// Number of byte in the values array
  uint16_t count;
  /// Initial values of the static field array
  uint8_t value[/* count */];

  JCVMArray<const uint8_t> values() const noexcept {
    return JCVMArray<const uint8_t>(NTOHS(count), value);
  }
};

struct __attribute__((__packed__)) jc_cap_static_field_component {
  /// Component tag: COMPONENT_StaticField (8)
  uint8_t tag;
  /// Component size
  uint16_t size;
  /// Bytes required to represent the static fields
  uint16_t image_size;
  /// Number of reference type static fields
  uint16_t reference_count;
  /// Number of elements in the array_init array
  uint16_t array_init_count;
  /// The rest of the component
  uint8_t data[];
  // {
  //   /// Initial value of primitive types
  //   struct jc_cap_array_init_info array_init [ /* array_init_count */ ];
  //   /// Number of bytes required to initialize the set of static fields
  //   uint16_t default_value_count;
  //   /// represents the number bytes in the non_default_values array
  //   uint16_t non_default_value_count;
  //   /// bytes of non-default initial values
  //   uint8_t non_default_values [ /* non_default_values_count */ ];
  // }

  uint16_t default_value_count() const noexcept {
    return BYTES_TO_SHORT(
        data[array_init_count * sizeof(jc_cap_array_init_info)],
        data[array_init_count * sizeof(jc_cap_array_init_info) + 1]);
  }

  uint16_t non_default_value_count() const noexcept {
    return BYTES_TO_SHORT(
        data[array_init_count * sizeof(jc_cap_array_init_info) +
             sizeof(uint16_t)],
        data[array_init_count * sizeof(jc_cap_array_init_info) +
             sizeof(uint16_t) + 1]);
  }

  JCVMArray<const uint8_t> non_default_values() const noexcept {
    return JCVMArray<const uint8_t>(
        non_default_value_count(),
        (data + array_init_count * sizeof(jc_cap_array_init_info) +
         2 * sizeof(uint16_t)));
  }
};

} // namespace jcvm

#endif /* _JC_CAP_STATIC_FIELD_HPP */
