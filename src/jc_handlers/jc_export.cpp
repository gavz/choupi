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

#include "jc_export.hpp"

namespace jcvm {

/*
 * Get an exported class from a class offset
 *
 * @param[class_export_offset] exported class offset to resolve.
 *
 * @return class_export associated to the input offset.
 */
const jc_cap_class_export_info &
Export_Handler::getExportedClass(const uint16_t class_export_offset) const
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
    noexcept
#endif
{
  const JC_Cap &cap = this->package.getCap();
  const jc_cap_export_component *export_component = cap.getExport();

#ifdef JCVM_DYNAMIC_CHECKS_CAP

  if (export_component == nullptr) { // No export component found!
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_DYNAMIC_CHECKS_CAP */

  return export_component->classexport(class_export_offset);
}

/*
 * Get an exported class index on the class component
 *
 *  @param[class_export_offset] exported class offset to resolve.
 *
 * @return class offset on the class component.
 */
const jclass_index_t
Export_Handler::getExportedClassOffset(const uint16_t class_export_offset) const
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
    noexcept
#endif
{
  auto class_import_info = this->getExportedClass(class_export_offset);

  return static_cast<jclass_index_t>(class_import_info.class_offset);
}

/**
 * Get static method offset in the method component from static method offset
 * in the Export component.
 *
 * @param[class_export_offset] exported class offset to resolve.
 * @param[static_method_offset] static method offset.
 * @return static method offset in the method component.
 */
uint16_t Export_Handler::getExportedStaticMethodOffset(
    const uint16_t class_export_offset,
    const uint8_t static_method_offset) const
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
    noexcept
#endif
{
  const jc_cap_class_export_info &exported_class =
      this->getExportedClass(class_export_offset);

  const JCVMArray<const uint16_t> method_offsets =
      exported_class.static_method_offsets();

  return HTONS(method_offsets.at(static_method_offset));
}

/**
 * Get static field offset in the Static field component from static method
 * offset in the Export component.
 *
 * @param[class_export_offset] exported class offset to resolve.
 * @param[static_field_offset] static method offset.
 * @return static field offset in the Static Field component.
 */
uint16_t Export_Handler::getExportedStaticFieldOffset(
    const uint16_t class_export_offset, const uint8_t static_field_offset) const
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
    noexcept
#endif
{
  const jc_cap_class_export_info &exported_class =
      this->getExportedClass(class_export_offset);

  const JCVMArray<const uint16_t> field_offsets =
      exported_class.static_field_offsets();

  return HTONS(field_offsets.at(static_field_offset));
}

} // namespace jcvm
