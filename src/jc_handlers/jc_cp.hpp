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

#ifndef _JC_CONSTANT_POOL_HPP
#define _JC_CONSTANT_POOL_HPP

#include "../jc_config.h"

#include "../exceptions.hpp"
#include "../jc_cap/jc_cap_cp.hpp"
#include "../jc_utils.hpp"
#include "../types.hpp"
#include "jc_component.hpp"
#include "package.hpp"

#include <utility>

namespace jcvm {

class ConstantPool_Handler : public Component_Handler {
public:
  /// Default constructor
  ConstantPool_Handler(Package package) noexcept : Component_Handler(package){};

  std::pair<jpackage_ID_t, jclass_index_t>
  getClassInformation(const jc_cp_offset_t instantiated_class)
#ifndef JCVM_ARRAY_SIZE_CHECK
      noexcept
#endif /* JCVM_ARRAY_SIZE_CHECK */
      ;

  ///  Get a cp_entry
  const jc_cap_constant_pool_info getCPEntry(const jc_cp_offset_t offset)
#ifndef JCVM_ARRAY_SIZE_CHECK
      noexcept
#endif /* JCVM_ARRAY_SIZE_CHECK */
      ;

  /// Converting a union cap_class_ref to either jc_cap_class or
  /// jc_cap_interface structure.
  std::pair<Package, const uint8_t *>
  resolveClassref(const jc_cap_class_ref classref)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;

  /// Convert constant pool offset to jc_class_ref
  const jc_cap_class_ref getClassRef(const jc_cp_offset_t offset)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;

  // Convert class index to jc_cap_class_info *
  const jc_cap_class_info *
  getClassFromClassIndex(const jclass_index_t claz_index)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;

  /// Convert class index to internal class ref
  const jc_cap_class_ref
  getClassRefFromClassIndex(const jclass_index_t claz_index);

  ///  Convert constant pool offset to struct jc_cap_virtual_method_ref_info
  const jc_cap_instance_field_ref_info
  getInstanceFieldRef(const jc_cp_offset_t offset)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;

  /// Convert constant pool offset to struct jc_cap_virtual_method_ref_info
  const jc_cap_virtual_method_ref_info
  getVirtualMethodRef(const jc_cp_offset_t offset)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;

  ///  Convert constant pool offset to struct jc_cap_super_method_ref_info
  const jc_cap_super_method_ref_info
  getSuperMethodRef(const jc_cp_offset_t offset)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;

  /// Convert jc_class_ref to struct jc_cap_interface structure.
  std::pair<Package, const jc_cap_class_info *>
  classref2class(const jc_cap_class_ref classref)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;
  /// Convert jc_class_ref to struct jc_cap_interface structure.
  std::pair<Package, const jc_cap_interface_info *>
  classref2interface(const jc_cap_class_ref classref)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;

  const jc_cap_static_field_ref_info
  getStaticFieldRefInfo(const jc_cp_offset_t offset)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;

  const jc_cap_static_method_ref_info
  getStaticMethodRefInfo(const jc_cp_offset_t offset)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;
};

} // namespace jcvm

#endif /* _JC_CONSTANT_POOL_HPP */
