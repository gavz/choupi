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

#ifndef _JC_CAP_HPP
#define _JC_CAP_HPP

#include "../jc_cap/jc_cap_applet.hpp"
#include "../jc_cap/jc_cap_class.hpp"
#include "../jc_cap/jc_cap_cp.hpp"
#include "../jc_cap/jc_cap_descriptor.hpp"
#include "../jc_cap/jc_cap_directory.hpp"
#include "../jc_cap/jc_cap_export.hpp"
#include "../jc_cap/jc_cap_header.hpp"
#include "../jc_cap/jc_cap_import.hpp"
#include "../jc_cap/jc_cap_method.hpp"
#include "../jc_cap/jc_cap_reference_location.hpp"
#include "../jc_cap/jc_cap_static_field.hpp"
#include "../jc_config.h"
#include "../types.hpp"

namespace jcvm {
// FIXME: Currently, only the CAP file version 2.1 is implemented
class JC_Cap {
private:
  /// Pointer to the header component
  const jc_cap_header_component *header_comp = nullptr;
  /// Pointer to the directory component
  const jc_cap_directory_component *directory_comp = nullptr;
  /// Pointer to the import component
  const jc_cap_import_component *import_comp = nullptr;
  /// Pointer to the applet component
  const jc_cap_applet_component *applet_comp = nullptr;
  /// Pointer to the class component
  const jc_cap_class_component *class_comp = nullptr;
  /// Pointer to the method component
  const jc_cap_method_component *method_comp = nullptr;
  /// Pointer to the static field component
  const jc_cap_static_field_component *staticField_comp = nullptr;
  /// Pointer to the export component
  const jc_cap_export_component *export_comp = nullptr;
  /// Pointer to the constant pool component
  const jc_cap_constant_pool_component *constantPool_comp = nullptr;
  /// Pointer to the reference location component
  const jc_cap_reference_location_component *referenceLocation_comp = nullptr;
  /// Pointer to the descriptor component
  const jc_cap_descriptor_component *descriptor_comp = nullptr;

public:
  /// default constructor
  JC_Cap(uint16_t length, const uint8_t *cap_file);
  JC_Cap(const JC_Cap &cap) noexcept = default;
  /// Copy assignment operator
  JC_Cap &operator=(const JC_Cap &cap) noexcept;
  /// Move assignment operator
  JC_Cap &operator=(const JC_Cap &&cap) noexcept;

  /// Equality operator
  bool operator==(JC_Cap &cap) const noexcept;

  /// Get Header component
  const jc_cap_header_component *getHeader() const noexcept;
  /// Get Directory component
  const jc_cap_directory_component *getDirectory() const noexcept;
  /// Get Import component
  const jc_cap_import_component *getImport() const noexcept;
  /// Get Applet component
  const jc_cap_applet_component *getApplet() const noexcept;
  /// Get Class component
  const jc_cap_class_component *getClass() const noexcept;
  /// Get Method component
  const jc_cap_method_component *getMethod() const noexcept;
  /// Get StaticField component
  const jc_cap_static_field_component *getStaticField() const noexcept;
  /// Get Export component
  const jc_cap_export_component *getExport() const noexcept;
  /// Get ConstantPool component
  const jc_cap_constant_pool_component *getConstantPool() const noexcept;
  /// Get ReferenceLocation component
  const jc_cap_reference_location_component *getReferenceLocation() const
      noexcept;
  /// Get Descriptor component
  const jc_cap_descriptor_component *getDescriptor() const noexcept;
};

} // namespace jcvm

#endif /* _JC_CAP_HPP */
