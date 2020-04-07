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

#ifndef _JC_CAP_EXPORT_HPP
#define _JC_CAP_EXPORT_HPP

#include "../jc_utils.hpp"
#include "../jcvm_types/jcvmarray.hpp"
#include "../types.hpp"

namespace jcvm {

struct __attribute__((__packed__)) jc_cap_class_export_info {
  /// Offset of the exported class component
  uint16_t class_offset;
  /// Number of elements in the static_field_offsets array
  uint8_t static_field_count;
  /// Number of elements in the static_method_offsets array
  uint8_t static_method_count;
  uint16_t data[/* static_field_count + static_method_count */];
  // {
  //   /// List each static field in the static field component
  //   uint16_t static_field_offsets [/* static_field_count */];
  //   /// List each static method in the Method component
  //   uint16_t static_method_offsets [/* static_method_count */];
  // }

  const JCVMArray<const uint16_t> static_field_offsets() const noexcept {
    return JCVMArray<const uint16_t>(static_field_count, data);
  }

  const JCVMArray<const uint16_t> static_method_offsets() const noexcept {
    return JCVMArray<const uint16_t>(
        static_method_count, (data + static_field_count * sizeof(uint16_t)));
  }

  uint16_t getSizeOf() const noexcept {
    return sizeof(jc_cap_class_export_info) +
           (static_field_count + static_method_count) * sizeof(uint16_t);
  }
};

struct __attribute__((__packed__)) jc_cap_export_component {
  /// Component tag: COMPONENT_Export (10)
  uint8_t tag;
  /// Component size
  uint16_t size;
  /// Number of entries in the class_exports table
  uint8_t class_count;
  /// List of each public classes and public interface defined
  uint8_t class_exports[/* class_count */];

  const jc_cap_class_export_info &classexport(const uint16_t index) const
#ifdef JCVM_ARRAY_SIZE_CHECK
      noexcept(false)
#else
      noexcept
#endif /* JCVM_ARRAY_SIZE_CHECK */
  {
#ifdef JCVM_ARRAY_SIZE_CHECK

    if (this->class_count <= index) {
      throw Exceptions::SecurityException;
    }

#endif /* JCVM_ARRAY_SIZE_CHECK */

    uint16_t offset = 0;

    for (uint16_t foo = 0; foo < index; ++foo) {
      const uint8_t *class_export_info = class_exports + offset;
      auto exported_class =
          reinterpret_cast<const jc_cap_class_export_info *>(class_export_info);
      offset += exported_class->getSizeOf();
    }

    const jc_cap_class_export_info *ret =
        reinterpret_cast<const jc_cap_class_export_info *>(class_exports +
                                                           offset);
    return *ret;
  }
};

} // namespace jcvm

#endif /* _JC_CAP_EXPORT_HPP */
