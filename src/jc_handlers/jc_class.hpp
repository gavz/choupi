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

#ifndef _JC_CLASS_HPP
#define _JC_CLASS_HPP

#include "../exceptions.hpp"
#include "../jc_cap/jc_cap_cp.hpp"
#include "../jc_config.h"
#include "../jc_utils.hpp"
#include "../types.hpp"
#include "jc_component.hpp"

#include <utility>

namespace jcvm {

class Class_Handler : public Component_Handler {
private:
  /// Get a class package method offset from a class' package method token.
  std::pair<Package, const uint16_t> getPublicMethodOffset(
      const jc_cap_virtual_method_ref_info virtual_method_ref_info)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;

  /// Do get a class public method offset from a class' public method token.
  std::pair<Package, const uint16_t>
  doGetPublicMethodOffset(Package &package, const jc_cap_class_info *claz,
                          uint8_t public_method_offset)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;

  /// Get a class package method offset from a class' package method token.
  std::pair<Package, const uint16_t> getPackageMethodOffset(
      const jc_cap_virtual_method_ref_info virtual_method_ref_info)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;

  /**
   * Check if two interfaces (interface_in and interface_out) have a hierarchy
   * link together. This function returns TRUE when interface_in is the
   * daughter of interface_out.
   */
  static jbool_t
  checkInterfaceCast(const std::pair<Package, const uint8_t *> interface_in,
                     const std::pair<Package, const uint8_t *> interface_out)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;

public:
  Class_Handler(Package package) : Component_Handler(package){};

  /// do check interface type compatibility
  static jbool_t
  docheckcast(const std::pair<Package, const uint8_t *> jtype_in,
              const std::pair<Package, const uint8_t *> jtype_out)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;

  /// Get the reference to the Object class from an objectref.
  std::pair<Package, const jc_cap_class_info *>
  getObjectClassFromAnObjectRef(const jc_cap_class_ref classref)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;

  /// Get public or package method offset  from a class' package method token.
  std::pair<Package, const uint16_t>
  getMethodOffset(const jc_cap_virtual_method_ref_info virtual_method_ref_info)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;

  /// Get a class' implemented interface method offset from a class' package
  /// method token.
  std::pair<Package, const uint16_t> getImplementedInterfaceMethodOffset(
      const jc_cap_class_ref class_ref, const jc_cap_class_ref interface,
      const uint8_t implemented_interface_method_number,
      const bool isArray = false)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;

  /// Get the instance field size for an instantiated class.
  const uint16_t getInstanceFieldsSize(const jclass_index_t claz_index) const
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
      noexcept
#endif
      ;
};

} // namespace jcvm
#endif /* _JC_CLASS_HPP */
