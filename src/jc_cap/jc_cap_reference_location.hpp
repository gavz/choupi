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

#ifndef _JC_CAP_REFERENCE_LOCATION_HPP
#define _JC_CAP_REFERENCE_LOCATION_HPP

#include "../jc_config.h"
#include "../jc_utils.hpp"
#include "../jcvm_types/jcvmarray.hpp"
#include "../types.hpp"

namespace jcvm {

struct __attribute__((__packed__)) jc_cap_reference_location_component {
  /// Component tag: COMPONENT_ReferenceLocation (9)
  uint8_t tag;
  /// Component size
  uint16_t size;
  uint8_t data[/* size */];
  // {
  //   /// Number of elements in the offsets_to_byte2_indices array
  //   uint16_t byte_index_count;
  //   /// 1-byte token offset in the Method component
  //   uint8_t offsets_to_byte_indices [/* byte_index_count */];
  //   /// Number of elements in the offsets_to_byte2_indices array
  //   uint16_t byte2_index_count;
  //   /// 2-byte token offset in the Method component
  //   uint8_t offsets_to_byte2_indices [/* byte2_index_count */];
  // }

  uint16_t byte_index_count() const noexcept {
    return BYTES_TO_SHORT(data[0], data[1]);
  }

  JCVMArray<const uint8_t> offsets_to_byte_indices() const noexcept {
    return JCVMArray<const uint8_t>(byte_index_count(),
                                    (data + sizeof(uint16_t)));
  }

  uint16_t byte2_index_count() const noexcept {
    return BYTES_TO_SHORT(data[byte_index_count() + sizeof(uint16_t)],
                          data[byte_index_count() + sizeof(uint16_t) + 1]);
  }

  const JCVMArray<const uint8_t> offsets_to_byte2_indices() const noexcept {
    return JCVMArray<const uint8_t>(
        byte2_index_count(),
        (data + byte_index_count() + 2 * sizeof(uint16_t)));
  }
};

} // namespace jcvm

#endif /* _JC_CAP_REFERENCE_LOCATION_HPP */
