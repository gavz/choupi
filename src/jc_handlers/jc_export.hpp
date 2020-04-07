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

#ifndef _JC_EXPORT_HPP
#define _JC_EXPORT_HPP

#include "../jc_config.h"

#include "../jc_cap/jc_cap_export.hpp"
#include "../types.hpp"
#include "jc_component.hpp"

namespace jcvm {

class Export_Handler : public Component_Handler {
public:
  /// Default constructor
  Export_Handler(Package package) noexcept : Component_Handler(package){};

  /// Get an exported class from a class offset
  const jc_cap_class_export_info &
  getExportedClass(const uint16_t class_export_offset) const
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;

  /// Get an exported class index on the class component
  const jclass_index_t
  getExportedClassOffset(const uint16_t class_export_offset) const
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;

  /// Get static field offset in the Static field component from static
  /// method offset in the Export component.
  uint16_t getExportedStaticFieldOffset(const uint16_t class_export_offset,
                                        const uint8_t static_field_offset) const
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;

  /// Get static method offset in the method component from static method offset
  /// in the Export component.
  uint16_t
  getExportedStaticMethodOffset(const uint16_t class_export_offset,
                                const uint8_t static_method_offset) const
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;
};

} // namespace jcvm

#endif /* _JC_EXPORT_HPP */
