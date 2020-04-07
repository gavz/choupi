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

#ifndef _JC_CAP_DESCRIPTOR_HPP
#define _JC_CAP_DESCRIPTOR_HPP

#include "../jcvm_types/jcvmarray.hpp"
#include "../types.hpp"
#include "jc_cap_cp.hpp"

namespace jcvm {

struct __attribute__((__packed__)) jc_cap_type_descriptor {
  /// Number of nibbles required to describe the type encoded in the type
  /// array
  uint8_t nibble_count;
  /// Encoded description of the type
  uint8_t type[/* (nibble_count+1) / 2 */];
};

struct __attribute__((__packed__)) jc_cap_field_descriptor_info {
  /// Token of this field
  uint8_t token;
  /// Describe the access permission to and properties of this field
  uint16_t access_flags;
  /// Reference to this field
  union {
    jc_cap_static_field_ref static_field;
    jc_cap_instance_field_ref_info instance_field;
  } field_ref;
  /// Type of this field, directly or indirectly
  union {
    /// Primitive type of the field
    uint16_t primitive_type;
    /// Represents a 15-bit offset into the type_descriptor_info structure
    uint16_t reference_type;
  } type;
};

struct __attribute__((__packed__)) jc_cap_method_descriptor_info {
  /// Token of this method
  uint8_t token;
  /// Describe the access permission to and properties of this method
  uint8_t access_flags;
  /// Method offset in the Method component of the described method
  uint16_t method_offset;
  /// Offset into the type_descriptor_info which represents the method
  /// signature
  uint16_t type_offset;
  /// Represents the number of bytecodes in this method
  uint16_t bytecode_count;
  /// Represents the number of exception handlers implemented by this method
  uint16_t exception_handler_count;
  /// Represents the index to the first exception_handlers table entry in
  /// the method component
  uint16_t exception_handler_index;
};

struct __attribute__((__packed__)) jc_cap_type_descriptor_info {
  /// Number of entries in the constant_pool_types array
  uint16_t constant_pool_count;
  uint8_t data[];
  // {
  //   /// Describes the types of the fields and methods referenced in the
  //   /// Constant Pool Component
  //   uint16_t constant_pool_types [ /* constant_pool_count */ ];
  //   /// Represents the types of fields and signatures of methods
  //   struct jc_cap_type_descriptor type_desc [];
  // }

  const JCVMArray<const uint16_t> constant_pool_types() const noexcept {
    return JCVMArray<const uint16_t>(NTOHS(constant_pool_count),
                                     reinterpret_cast<const uint16_t *>(data));
  }

  const jc_cap_type_descriptor *type_desc() const noexcept {
    return reinterpret_cast<const jc_cap_type_descriptor *>(
        data + NTOHS(constant_pool_count) * sizeof(uint8_t));
  }
};

struct __attribute__((__packed__)) jc_cap_class_descriptor_info {
  /// Class or interface token
  uint8_t token;
  /// Mask of modifiers used to describe the access permission
  uint8_t access_flags;
  /// Link to the class_info in the Class component
  union jc_cap_class_ref this_class_ref;
  /// Number of entries in the interfaces array
  uint8_t interface_count;
  /// Number of entries in the fields array
  uint16_t field_count;
  /// Number of entries in the methods array
  uint16_t method_count;
  uint8_t data[/* interface_count + field_count + method_count */];
  // {
  //   /// Represents an array of interfaces implemented by this class
  //   union jc_cap_class_ref interfaces [ /* interface_count */ ];
  //   /// Represents an array of field_descriptor_info structures
  //   struct jc_cap_field_descriptor_info fields [ /* field_count */ ];
  //   /// Represents an array of method_descriptor_info structures
  //   struct jc_cap_method_descriptor_info methods [ /* method_count */ ];
  // }

  const JCVMArray<const jc_cap_class_ref> interfaces() const noexcept {
    return JCVMArray<const jc_cap_class_ref>(interface_count,
                                             (jc_cap_class_ref *)data);
  }

  const JCVMArray<const jc_cap_field_descriptor_info> fields() const noexcept {
    return JCVMArray<const jc_cap_field_descriptor_info>(
        NTOHS(field_count),
        (jc_cap_field_descriptor_info *)(data +
                                         interface_count *
                                             sizeof(union jc_cap_class_ref)));
  }

  const JCVMArray<const jc_cap_method_descriptor_info> methods() const
      noexcept {
    return JCVMArray<const jc_cap_method_descriptor_info>(
        NTOHS(method_count),
        (const jc_cap_method_descriptor_info
             *)(data + interface_count * sizeof(jc_cap_class_ref) +
                NTOHS(field_count) * sizeof(jc_cap_field_descriptor_info)));
  }
};

struct __attribute__((__packed__)) jc_cap_descriptor_component {
  /// Component tag: COMPONENT_descriptor (11).
  uint8_t tag;
  /// Component size
  uint16_t size;
  /// Number of entries in the classes table.
  uint8_t class_count;
  uint8_t data[];
  // {
  //   /// Represented each class and interface defined in this package
  //   struct jc_cap_class_descriptor_info classes [ /* class_count */ ];
  //   /// Lists field types and method signatures of the fields and methods
  //   /// defined or referenced in this package.
  //   struct jc_cap_type_descriptor_info types;
  // }

  const jc_cap_class_descriptor_info *classes() const noexcept {
    return reinterpret_cast<const jc_cap_class_descriptor_info *>(data);
  }

  const jc_cap_type_descriptor_info *types() const noexcept {
    return reinterpret_cast<const jc_cap_type_descriptor_info *>(
        data + class_count * sizeof(struct jc_cap_class_descriptor_info));
  }
};

} // namespace jcvm

#endif /* _JC_CAP_DESCRIPTOR_HPP */
