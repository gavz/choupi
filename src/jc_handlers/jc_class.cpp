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

#include "jc_class.hpp"
#include "jc_cp.hpp"

namespace jcvm {

/*
 * The checkcast function check if a type in is compatible with the
 * type_out. The rule is the following one:
 *
 * - If S is a class type, then:
 *     + If T is a class type, then S must be the same class as T, or
 *       S must be a subclass of T;
 *     + If T is an interface type, then S must implement interface T.
 * - If S is an interface type[13], then:
 *     + If T is a class type, then T must be Object (§2.2.1.4
 *       Unsupported Classes);
 *     + If T is an interface type, T must be the same interface as S
 *       or a superinterface of S.
 * - If S is an array type, namely the type SC[], that is, an array of
 *   components of type SC, then:
 *     + If T is a class type, then T must be Object.
 *     + If T is an array type, namely the type TC[], an array of
 *       components of type TC, then one of the following must be true:
 *         * TC and SC are the same primitive type (§3.1 Data Types and
 *           Values).
 *         * TC and SC are reference types[14] (§3.1 Data Types and Values)
 *           with type SC assignable to TC, by these rules.
 *     + If T is an interface type, T must be one of the interfaces
 *       implemented by arrays.
 *
 * 13: When both S and T are arrays of reference types, this algorithm is
 * applied recursively using the types of the arrays, namely SC and TC. In
 * the recursive call, S, which was SC in the original call, may be an
 * interface type. This rule can only be reached in this manner.
 * Similarly, in the recursive call, T, which was TC in the original call,
 * may be an interface type.
 *
 * @param[jtype_in] the input type
 * @param[jtype_out] the out type
 *
 * @return TRUE if the types are compatible, else FALSE
 */
jbool_t
Class_Handler::docheckcast(const std::pair<Package, const uint8_t *> jtype_in,
                           const std::pair<Package, const uint8_t *> jtype_out)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
    noexcept
#endif
{
  // case 1: type_in is a class type
  if (IS_CLASS(jtype_in.second)) {
    auto jclass_in = std::make_pair(
        jtype_in.first,
        reinterpret_cast<const jc_cap_class_info *>(jtype_in.second));

    // case 1.1: type_out is a class type
    if (IS_CLASS(jtype_out.second)) {
      auto jclass_out =
          reinterpret_cast<const jc_cap_class_info *>(jtype_out.second);

      // then S must be the same class as T, or S must be a subclass of T
      if (jclass_out->isObjectClass()) {
        return TRUE;
      }

      while (!jclass_in.second->isObjectClass()) {
        if (jclass_in.second == jclass_out) {
          return TRUE;
        }

        jclass_in = ConstantPool_Handler(jclass_in.first)
                        .classref2class(jclass_in.second->super_class_ref);
      }

      return FALSE;
    }
    // case 1.2: type_out is an interface type
    else {
      if (jclass_in.second->interface_count == 0) {
        return FALSE;
      }

      for (uint8_t i = 0; i < jclass_in.second->interface_count; ++i) {
        auto implemented_interface = jclass_in.second->interfaces(i);
        ConstantPool_Handler cp(jclass_in.first);

        if (Class_Handler::checkInterfaceCast(
                cp.resolveClassref(implemented_interface.interface),
                jtype_out) == TRUE) {
          return TRUE;
        }
      }
    }
  }

  // case 2: type_in is an interface type
  else {
    // jtype_out must be Object
    if (IS_CLASS(jtype_out.second)) {
      const auto jclass_out = std::make_pair(
          jtype_out.first,
          reinterpret_cast<const jc_cap_class_info *>(jtype_out.second));
      return (jclass_out.second->isObjectClass() ? TRUE : FALSE);
    }

    return Class_Handler::checkInterfaceCast(jtype_in, jtype_out);
  }

  return FALSE;
}

/*
 * Check if two interfaces (interface_in and interface_out) have a hierarchy
 * link together. This function returns TRUE when interface_in is the
 * daughter of interface_out.
 *
 * @param[interface_in]
 * @param[interface_out]
 *
 * @return returns TRUE when interface_in is the daughter of interface_out
 */
jbool_t Class_Handler::checkInterfaceCast(
    const std::pair<Package, const uint8_t *> interface_in,
    const std::pair<Package, const uint8_t *> interface_out)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
    noexcept
#endif
{

#ifdef JCVM_DYNAMIC_CHECKS_CAP

  if (!IS_INTERFACE(interface_in.second) ||
      !IS_INTERFACE(interface_out.second)) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_DYNAMIC_CHECKS_CAP */

  auto superinterfaces =
      reinterpret_cast<const jc_cap_interface_info *>(interface_in.second)
          ->super_interfaces();

  for (uint8_t j = 0; j < superinterfaces.size(); ++j) {
    const jc_cap_class_ref super_interface_in = superinterfaces.at(j);

    auto super_interface_ptr = ConstantPool_Handler(interface_in.first)
                                   .resolveClassref(super_interface_in);

#ifdef JCVM_DYNAMIC_CHECKS_CAP

    if (!IS_INTERFACE(super_interface_ptr.second)) {
      throw Exceptions::SecurityException;
    }

#endif /* JCVM_DYNAMIC_CHECKS_CAP */

    if ((super_interface_ptr.first == interface_out.first) &&
        (super_interface_ptr.second == interface_out.second)) {
      return TRUE;
    }
  }

  return FALSE;
}

/*
 * Get the reference to the Object class from a classref.
 *
 * @param[classref] a classref to find this ultimate class.
 * @return the reference to the Object class.
 */
std::pair<Package, const jc_cap_class_info *>
Class_Handler::getObjectClassFromAnObjectRef(const jc_cap_class_ref classref)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
    noexcept
#endif
{
  ConstantPool_Handler cp_handler(this->package);
  auto token = cp_handler.classref2class(classref);

  while (!(token.second->isObjectClass())) {
    cp_handler.setPackage(token.first);
    token = cp_handler.classref2class(token.second->super_class_ref);
  }

  return token;
}

/**
 * Get a class public method offset from a class' public method token.
 *
 * @param[public_method_token] public method token to resolve.
 *
 * @return the public virtual method offset in the Method component.
 */
std::pair<Package, const uint16_t> Class_Handler::getPublicMethodOffset(
    const jc_cap_virtual_method_ref_info virtual_method_ref_info)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
    noexcept
#endif
{
#ifdef JCVM_DYNAMIC_CHECKS_CAP

  if (virtual_method_ref_info.isPublicMethod()) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_DYNAMIC_CHECKS_CAP */

  ConstantPool_Handler cp_handler(this->package);
  uint8_t method_offset = virtual_method_ref_info.token;
  auto token = cp_handler.classref2class(virtual_method_ref_info.class_ref);

  // Where is the method offset located?
  while (!(token.second->isObjectClass()) &&
         (method_offset < token.second->public_method_table_base)) {
    // Jump to superclass
    cp_handler.setPackage(token.first);
    token = cp_handler.classref2class(token.second->super_class_ref);
  }

#ifdef JCVM_DYNAMIC_CHECKS_CAP

  if (token.second->isObjectClass() &&
      (method_offset < token.second->public_method_table_base)) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_DYNAMIC_CHECKS_CAP */

  return this->doGetPublicMethodOffset(token.first, token.second,
                                       method_offset);
}

/**
 * Do get a class public method offset from a class' public method token.
 *
 * @param[package] where is located the method to resolve
 * @param[claz] a pointer to the class where is located the method to resolve
 * @param[public_method_token] public method token to resolve.
 *
 * @return the public virtual method offset in the Method component.
 */
std::pair<Package, const uint16_t>
Class_Handler::doGetPublicMethodOffset(Package &package,
                                       const jc_cap_class_info *claz,
                                       uint8_t public_method_offset)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
    noexcept
#endif
{
  ConstantPool_Handler cp_handler(this->package);

  uint16_t method_offset = 0xFFFF;
  const JCVMArray<const uint16_t> public_virtual_method_table =
      claz->public_virtual_method_table();
  auto token = std::make_pair(package, claz);

  do {
    uint16_t offset = public_method_offset - claz->public_method_table_base;
    method_offset = public_virtual_method_table.at(offset);

    if (method_offset == (uint16_t)0xFFFF) {
#ifdef JCVM_DYNAMIC_CHECKS_CAP

      if (claz->isObjectClass()) {
        // Behaviour not expected
        throw Exceptions::SecurityException;
      }

#endif /* JCVM_DYNAMIC_CHECKS_CAP */

      // Jump to superclass
      cp_handler.setPackage(token.first);
      token = cp_handler.classref2class(token.second->super_class_ref);
    }
  } while (method_offset == (uint16_t)0xFFFF);

  return std::make_pair(token.first, method_offset);
}

/**
 * Get a class package method offset from a class' package method token.
 *
 * @param[package_method_token] package method token to resolve.
 *
 * @return the package virtual method offset in the Method component. The Cap
 * field is updated to executed the method to call.
 */
std::pair<Package, const uint16_t> Class_Handler::getPackageMethodOffset(
    const jc_cap_virtual_method_ref_info virtual_method_ref_info)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
    noexcept
#endif
{
#ifdef JCVM_DYNAMIC_CHECKS_CAP

  if (!virtual_method_ref_info.isPublicMethod()) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_DYNAMIC_CHECKS_CAP */

  ConstantPool_Handler cp_handler(this->package);
  uint8_t method_offset_class = virtual_method_ref_info.token;
  auto token = cp_handler.classref2class(virtual_method_ref_info.class_ref);

  // Where is the method offset located?
  while (!(token.second->isObjectClass()) &&
         (method_offset_class < token.second->package_method_table_base)) {
    // Jump to superclass
    cp_handler.setPackage(token.first);
    token = cp_handler.classref2class(token.second->super_class_ref);
  }

  uint16_t method_offset = 0xFFFF;
  const jc_cap_class_info *claz = token.second;
  const JCVMArray<const uint16_t> package_virtual_method_table =
      claz->package_virtual_method_table();

  do {
    uint16_t offset = method_offset_class - claz->package_method_table_base;
    method_offset = package_virtual_method_table.at(offset);

    if (method_offset == (uint16_t)0xFFFF) {
#ifdef JCVM_DYNAMIC_CHECKS_CAP

      if (claz->isObjectClass()) {
        // Behavior not expected
        throw Exceptions::SecurityException;
      }

#endif /* JCVM_DYNAMIC_CHECKS_CAP */

      // Jump to superclass
      cp_handler.setPackage(token.first);
      token = cp_handler.classref2class(token.second->super_class_ref);
    }
  } while (method_offset == (uint16_t)0xFFFF);

  return std::make_pair(token.first, method_offset);
}

/**
 * Get a class public or package method offset from a class' method token.
 *
 * @param[method_token] method token to resolve.
 *
 * @return the public or package virtual method offset in the Method component.
 */
std::pair<Package, const uint16_t> Class_Handler::getMethodOffset(
    const jc_cap_virtual_method_ref_info virtual_method_ref_info)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
    noexcept
#endif
{
  if (virtual_method_ref_info.isPublicMethod()) {
    return this->getPublicMethodOffset(virtual_method_ref_info);
  } else { // it's a package method
    return this->getPackageMethodOffset(virtual_method_ref_info);
  }
}

/*
 * Get a class' implemented interface method offset from a class' package method
 * token.
 *
 * @param[class] class where the method will be resolved.
 * @param[interface] implemented interface.
 * @param[implemented_interface_method_number] implemented interface method
 *                                              number.
 * @return the implemented interface method offset in the method component.
 */
std::pair<Package, const uint16_t>
Class_Handler::getImplementedInterfaceMethodOffset(
    const jc_cap_class_ref class_ref, const jc_cap_class_ref interface,
    const uint8_t implemented_interface_method_number, const bool isArray)
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
    noexcept
#endif
{
  ConstantPool_Handler cp_handler(this->package);
  auto claz = (isArray ? this->getObjectClassFromAnObjectRef(class_ref)
                       : cp_handler.classref2class(class_ref));

  for (uint16_t index = 0; index < claz.second->interface_count; ++index) {
    const auto &interfaces = claz.second->interfaces(index);

    if (HTONS(interfaces.interface.internal_classref) ==
        interface.internal_classref) {

      uint8_t public_method_offset =
          interfaces.indexes().at(implemented_interface_method_number);

      if (isArray) {
        return this->doGetPublicMethodOffset(claz.first, claz.second,
                                             public_method_offset);
      } else {
        const jc_cap_virtual_method_ref_info method_ref = {
            .class_ref = class_ref,
            .token = public_method_offset,
        };

        return this->getPublicMethodOffset(method_ref);
      }
    }
  }

  throw Exceptions::SecurityException;
}

/*
 * Get the instance field size for an instantiated class.
 *
 * @param[claz_index] class index used to compute the instance field size
 */
const uint16_t
Class_Handler::getInstanceFieldsSize(const jclass_index_t claz_index) const
#if !defined(JCVM_ARRAY_SIZE_CHECK) && !defined(JCVM_DYNAMIC_CHECKS_CAP)
    noexcept
#endif
{
  auto package = this->package;
  auto claz = ConstantPool_Handler(package).getClassFromClassIndex(claz_index);

  uint16_t instance_size = 0;

  do {
    ConstantPool_Handler cp_handler(package);
    instance_size += (claz->declared_instance_size & 0x00FF);
    auto pair = cp_handler.classref2class(claz->super_class_ref);
    package = pair.first;
    claz = pair.second;
  } while (!(claz->isObjectClass()));

  return instance_size;
}

} // namespace jcvm
