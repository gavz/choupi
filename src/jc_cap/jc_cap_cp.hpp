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

#ifndef _JC_CAP_CONSTANT_POOL_HPP
#define _JC_CAP_CONSTANT_POOL_HPP

#include "../jc_utils.hpp"
#include "../jcvm_types/jcvmarray.hpp"
#include "../types.hpp"

namespace jcvm {

struct __attribute__((__packed__)) jc_cap_external_classref_info {
  uint8_t package_token; /* Token of the package in the Import component */
  uint8_t class_token; /* Token of class or interface in the Import component */
};

union __attribute__((__packed__)) jc_cap_class_ref {
  uint16_t internal_classref; /* Class offset in the Class component */
  jc_cap_external_classref_info external_classref; /* Imported class info. */

  bool isExternalClassRef() const noexcept {
    return ((NTOHS(internal_classref) & (uint16_t)0x8000) != 0);
  }

  bool isInternalClassRef() const noexcept {
    return ((NTOHS(internal_classref) & (uint16_t)0x8000) == 0);
  }
};

struct __attribute__((__packed__)) jc_cap_class_ref_info {
  jc_cap_class_ref class_ref; /* Reference to a class or an interface */
  uint8_t padding;            /* 1-byte padding */
};

struct __attribute__((__packed__)) jc_cap_instance_field_ref_info {
  jc_cap_class_ref class_ref; /* Reference to the instanced class/instance */
  uint8_t token;              /* Instance field token */
};

struct __attribute__((__packed__)) jc_cap_virtual_method_ref_info {
  jc_cap_class_ref class_ref; /* Class which contains the virtual method */
  uint8_t token; /* Virtual method token of the referenced method */

  /**
   * Is a package method?
   */
  bool isPackageMethod() const { return ((token & 0x80) > 0); }

  /**
   * Is a public method?
   */
  bool isPublicMethod() const { return ((token & 0x80) == 0); }
};

struct __attribute__((__packed__)) jc_cap_super_method_ref_info {
  jc_cap_class_ref class_ref; /* Class which contains the super method */
  uint8_t token;              /* Super method token of the referenced method */
};

struct __attribute__((__packed__)) jc_cap_internal_ref {
  uint8_t padding; /* 1-byte padding */
  uint16_t offset; /* 16-bit offset into the Static Field Image */
};

struct __attribute__((__packed__)) jc_cap_external_ref {
  uint8_t package_token; /* Package token in the Import Component */
  uint8_t class_token;   /* Class token of the reference class */
  uint8_t token;         /* Static field token */
};

union __attribute__((__packed__)) jc_cap_static_field_ref {
  jc_cap_internal_ref internal_ref; /* reference to a static field in this
                                     * package */
  jc_cap_external_ref external_ref; /* reference to a static field defined
                                     * in an imported package */
};

struct __attribute__((__packed__)) jc_cap_static_field_ref_info {
  jc_cap_static_field_ref static_field_ref; /* Represents a reference to a
                                             * static field */
};

struct __attribute__((__packed__)) jc_cap_static_method_ref_info {
  union __attribute__((__packed__)) {
    jc_cap_internal_ref internal_ref; /* Represents a reference to a static
                                       * method defined in this package */
    jc_cap_external_ref external_ref; /* represents a reference to a static
                                       * method defined in an imported
                                       * package */
  } static_method_ref;
}; /* Represents a reference to a static method */

#define IS_CP_EXTERNAL_REF(ref)                                                \
  ((ref.external_ref.package_token & 0x80) == 0x80)
#define IS_CP_INTERNAL_REF(ref) (!IS_CP_EXTERNAL_REF(ref))

struct __attribute__((__packed__)) jc_cap_constant_pool_info {
  uint8_t tag; /* Constant pool entry tag */
  union {      // 3-Byte element
    jc_cap_class_ref_info class_ref_info;
    jc_cap_instance_field_ref_info instance_field_ref_info;
    jc_cap_virtual_method_ref_info virtual_method_ref_info;
    jc_cap_super_method_ref_info super_method_ref_info;
    jc_cap_static_field_ref_info static_field_ref_info;
    jc_cap_static_method_ref_info static_method_ref_info;
  } info;
};

#define JC_CP_TAG_CONSTANT_CLASSREF (uint8_t)1
#define JC_CP_TAG_CONSTANT_INSTANCEFIELDREF (uint8_t)2
#define JC_CP_TAG_CONSTANT_VIRTUALMETHODREF (uint8_t)3
#define JC_CP_TAG_CONSTANT_SUPERMETHODREF (uint8_t)4
#define JC_CP_TAG_CONSTANT_STATICFIELDREF (uint8_t)5
#define JC_CP_TAG_CONSTANT_STATICMETHODREF (uint8_t)6

struct __attribute__((__packed__)) jc_cap_constant_pool_component {
  uint8_t tag;    /* Tag component: COMPONENT_ConstantPool (5) */
  uint16_t size;  /* Component size */
  uint16_t count; /* Number of constant_pool entries */
  jc_cap_constant_pool_info constant_pool[/* count */]; /* constant pool
                                                         * entries */

  JCVMArray<const jc_cap_constant_pool_info> constantpool() const noexcept {
    return JCVMArray<const jc_cap_constant_pool_info>(HTONS(count),
                                                      constant_pool);
  }
};

} // namespace jcvm

#endif /* _JC_CAP_CONSTANT_POOL_HPP */
