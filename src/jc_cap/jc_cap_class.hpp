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

#ifndef _JC_CAP_CLASS_HPP
#define _JC_CAP_CLASS_HPP

#include "../jcvm_types/jcvmarray.hpp"
#include "../types.hpp"
#include "jc_cap_cp.hpp"

namespace jcvm {

struct __attribute__((__packed__)) jc_cap_implemented_interface_info {
  jc_cap_class_ref interface; /* Represents the implemented interface */
  uint8_t count;              /* Number of entries in the index[] array */
  uint8_t index[/* count */]; /* maps declarations of interface methods */

  const JCVMArray<const uint8_t> indexes() const noexcept {
    return JCVMArray<const uint8_t>(count, index);
  }

  uint16_t getSizeOf() const noexcept {
    return sizeof(jc_cap_implemented_interface_info) + count * sizeof(uint8_t);
  }
};

struct __attribute__((__packed__)) jc_cap_class_info {
#ifdef NVM_BIG_ENDIAN
  uint8_t flags : 4;                /* Class flags */
  uint8_t interface_count : 4;      /* Number of entries in the implemented
                             interfaces      table */
#else                               /* !NVM_BIG_ENDIAN */
  uint8_t interface_count : 4; /* Number of entries in the implemented
                        interfaces table */
  uint8_t flags : 4;           /* Class flags */
#endif                              /* NVM_BIG_ENDIAN */
  jc_cap_class_ref super_class_ref; /* super class of this class */
  uint8_t declared_instance_size;   /* Instance size in word */
  uint8_t
      first_reference_token; /* First reference in the instance field token */
  uint8_t reference_count; /* Number of reference in the type instance field */
  uint8_t public_method_table_base;  /* Public method table base */
  uint8_t public_method_table_count; /* Number of public method table entries */
  uint8_t package_method_table_base; /* Package method table base */
  uint8_t
      package_method_table_count; /* Number of package method table entries */
  uint16_t data[];
  // {
  //   uint16_t public_virtual_method_table [/* public_method_table_count */];
  //   uint16_t package_virtual_method_table [/* package_method_table_count */];
  //   struct jc_cap_implemented_interface_info interfaces [/* interface_count
  //   */];
  // }

  const uint16_t getSize() const noexcept {
    uint16_t size = sizeof(jc_cap_class_info) +
                    (public_method_table_count + package_method_table_count) *
                        sizeof(uint16_t);

    uint16_t position = public_method_table_count + package_method_table_count;

    for (uint8_t index = 0; index < interface_count; index++) {
      auto interface =
          reinterpret_cast<const jc_cap_implemented_interface_info *>(
              data[position]);

      uint16_t current_size = interface->getSizeOf();
      size += current_size;
      position += current_size / sizeof(uint16_t);
    }

    return size;
  }

  inline bool isObjectClass() const noexcept {
    return (NTOHS(super_class_ref.internal_classref) == (uint16_t)0xFFFF);
  }

  const JCVMArray<const uint16_t> public_virtual_method_table() const noexcept {
    return JCVMArray<const uint16_t>(public_method_table_count, data);
  }

  const JCVMArray<const uint16_t> package_virtual_method_table() const
      noexcept {
    return JCVMArray<const uint16_t>(
        package_method_table_count,
        (data + public_method_table_count * sizeof(uint16_t)));
  }

  const jc_cap_implemented_interface_info &
  interfaces(const uint16_t index) const
#ifdef JCVM_ARRAY_SIZE_CHECK
      noexcept(false)
#else
      noexcept
#endif /* JCVM_ARRAY_SIZE_CHECK */
  {
#ifdef JCVM_ARRAY_SIZE_CHECK

    if (interface_count <= index) {
      throw Exceptions::SecurityException;
    }

#endif /* JCVM_ARRAY_SIZE_CHECK */

    uint16_t offset = 0;
    const uint8_t *interfaces = reinterpret_cast<const uint8_t *>(
        &(data[public_method_table_count + package_method_table_count]));

    for (uint16_t foo = 0; foo < index; ++foo) {
      const jc_cap_implemented_interface_info *implemented_interface =
          reinterpret_cast<const jc_cap_implemented_interface_info *>(
              interfaces + offset);
      offset += implemented_interface->getSizeOf();
    }

    const jc_cap_implemented_interface_info *ret =
        reinterpret_cast<const jc_cap_implemented_interface_info *>(interfaces +
                                                                    offset);
    return *ret;
  }
};

struct __attribute__((__packed__)) jc_cap_interface_info {
#ifdef NVM_BIG_ENDIAN
  uint8_t flags : 4; /* Interface flags */
  uint8_t
      interface_count : 4; /* Number of entries in the superinterfaces table */
#else                      /* !NVM_BIG_ENDIAN */
  uint8_t
      interface_count : 4; /* Number of entries in the superinterfaces table */
  uint8_t flags : 4;       /* Interface flags */
#endif                     /* NVM_BIG_ENDIAN */
  /// Current interface's superclasses */
  jc_cap_class_ref superinterfaces[/* interface_count */];

  const JCVMArray<const jc_cap_class_ref> super_interfaces() const noexcept {
    return JCVMArray<const jc_cap_class_ref>(NTOHS(interface_count),
                                             superinterfaces);
  }

  const uint16_t getSize() const noexcept {
    return sizeof(jc_cap_interface_info) /* = 1 */ +
           interface_count * sizeof(jc_cap_class_ref) /* = 2 */;
  }
};

struct __attribute__((__packed__)) jc_cap_class_component {
  uint8_t tag;   /* Component Tag: COMPONENT_Class (6) */
  uint16_t size; /* Component size */
  uint8_t infos[/* size */];
  // {
  /**
   * The interfaces item represents an array of interface_info structures.
   * Each interface defined in this package is represented in the array. The
   * entries are ordered based on hierarchy such that a superinterface has a
   * lower index than any of its subinterfaces.
   */
  // struct jc_cap_interface_info interfaces[];
  /**
   * The classes item represents a table of variable-length class_info
   * structures. Each class defined in this package is represented in the
   * array. The entries are ordered based on hierarchy such that a
   * superclass has a lower index than any of its subclasses.
   */
  // struct jc_cap_class_info classes[];
  // }

  /*
    const struct jc_cap_interface_info * interfaces() const noexcept
  {
    return reinterpret_cast<struct jc_cap_interface_info *>(infos);
  }

  const struct jc_cap_class_info * classes() const noexcept
  {
    return reinterpret_cast<struct jc_cap_class_info *>(infos + ???);
  }
  */

  const JCVMArray<const uint8_t> claz() const noexcept {
    return JCVMArray<const uint8_t>(NTOHS(size), infos);
  }
};

#define JC_CAP_CLASS_ACC_INTERFACE (uint8_t)0x8
#define JC_CAP_CLASS_ACC_SHAREABLE (uint8_t)0x4
#define JC_CAP_CLASS_ACC_REMOTE (uint8_t)0x2

#define IS_INTERFACE(classref)                                                 \
  ((((uint8_t)(((jc_cap_interface_info *)classref)->flags)) &                  \
    JC_CAP_CLASS_ACC_INTERFACE))
#define IS_CLASS(classref) (!IS_INTERFACE(classref))

} // namespace jcvm

#endif /* _JC_CAP_CLASS_HPP */
