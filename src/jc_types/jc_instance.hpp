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

#ifndef _JC_INSTANCE_HPP
#define _JC_INSTANCE_HPP

#include "../jc_config.h"
#include "../jc_handlers/package.hpp"
#include "../jc_utils.hpp"
#include "../jcvm_types/jcvmarray.hpp"
#include "../types.hpp"
#include "jc_field.hpp"
#include "jc_object.hpp"
#include "jref_t.hpp"

namespace jcvm {

namespace fs {
struct Tag; // Forward declaration of Tag
}

class JC_Instance : public JC_Object {
private:
  jpackage_ID_t packageID;
  jclass_index_t claz;

  /**
   * Instance fields' values. Each element are encoded on one words (SHORT
   * and REFERENCE). According to the specification, the INTEGER, are
   * encoded on 2 words.
   */
  JCVMArray<jc_field_t> *fields = nullptr; // instance_length-length array

  fs::Tag recomputeOriginalTag() const noexcept;

public:
  JC_Instance(Heap &owner, const Package &package_owner,
              const jc_cp_offset_t instantiated_class) noexcept;
  JC_Instance(Heap &owner, const jpackage_ID_t packageID,
              const jclass_index_t claz_index) noexcept;
  JC_Instance(Heap &owner, const jpackage_ID_t packageID,
              const jclass_index_t claz_index, const fs::Tag &tag) noexcept;
  ~JC_Instance() noexcept;

  /// Get package ID
  jpackage_ID_t getPackageID() const noexcept;
  /// Get class index
  jclass_index_t getClassIndex() const noexcept;
  /// Set package ID
  void setPackageID(const jpackage_ID_t packageID) noexcept;
  /// Set class index
  void setClassIndex(const jclass_index_t class_index) noexcept;

  /// Fetch byte or boolean from object.
  const jbyte_t getField_Byte(const uint16_t index);
  /// Fetch short from object.
  const jshort_t getField_Short(const uint16_t index);
#ifdef JCVM_INT_SUPPORTED
  /// Fetch int from object.
  const jint_t getField_Int(const uint16_t index);
#endif /* JCVM_INT_SUPPORTED */
  /// Fetch reference from object.
  const jref_t getField_Reference(const uint16_t index);

  /// set byte or boolean field from object.
  void setField_Byte(const uint16_t index, const jbyte_t value);
  /// set short field from object.
  void setField_Short(const uint16_t index, const jshort_t value);
#ifdef JCVM_INT_SUPPORTED
  /// set int field from object.
  void setField_Int(const uint16_t index, const jint_t value);
#endif /* JCVM_INT_SUPPORTED */
  /// set reference field from object.
  void setField_Reference(uint16_t index, jref_t ref);

  ///  Get the number of instance field.
  auto getNumberOfFields() const noexcept -> decltype(fields->size());
  /// Get fields arrays
  auto getFields() const noexcept -> decltype(fields);
};

} // namespace jcvm

#endif /* _JC_INSTANCE_HPP */
