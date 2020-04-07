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

#include "jc_array.hpp"
#include "../jc_utils.hpp"
#include "ffi.h"
#include "jc_array_type.hpp"

#ifdef JCVM_FIREWALL_CHECKS
#include "../context.hpp"
#include "../heap.hpp"
#include "../jc_handlers/jc_class.hpp"
#include "../jc_handlers/jc_cp.hpp"
#endif /* JCVM_FIREWALL_CHECKS */

namespace jcvm {

/**
 * Constructor
 */
JC_Array::JC_Array(Heap &owner, const uint16_t size, const jc_array_type type,
                   const bool isTransientArray)
    : JC_Object(owner, !isTransientArray), type(type), reference_type(0xFFFF),
      array(size * JC_Array::getEntrySize(type)),
      isTransient(isTransientArray) {
#ifdef JCVM_SECURE_HEAP_ACCESS

  switch (this->type) {
  case JAVA_ARRAY_T_BOOLEAN:
  case JAVA_ARRAY_T_BYTE:
  case JAVA_ARRAY_T_SHORT:

#ifdef JCVM_INT_SUPPORTED
  case JAVA_ARRAY_T_INT:
#endif /* JCVM_INT_SUPPORTED */

    // everything fine
    break;

  default:
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */
}

/**
 * Constructor
 */
JC_Array::JC_Array(Heap &owner, const uint16_t size, const jc_array_type type,
                   const jc_cp_offset_t reference_type,
                   const bool isTransientArray)
    : JC_Object(owner, !isTransientArray), type(type),
      reference_type(reference_type), isTransient(isTransientArray),
      array(size * JC_Array::getEntrySize(type)) {}

/**
 * Constructor
 */
JC_Array::JC_Array(Heap &owner, const jc_array_type type,
                   const jc_cp_offset_t reference_type, const fs::Tag &tag,
                   const bool isTransientArray, const ClearEvent event,
                   const uint16_t length) noexcept
    : JC_Object(owner, true), type(type), reference_type(reference_type),
      array(tag.len + length * JC_Array::getEntrySize(type) + sizeof(uint8_t),
            new uint8_t[tag.len + length + sizeof(uint8_t)]),
      isTransient(isTransientArray), clear(event) {
  this->array[0] = tag.len;

  for (uint8_t idx = 0; idx < tag.len; idx++) {
    this->array[idx + 1] = tag.value[idx];
  }
}

/*
 * Default destructor
 */
JC_Array::~JC_Array() noexcept {
  if (this->isTransientArray()) {
    delete[] this->array.data();
  }
}

/*
 * Compute tag value
 *
 * @return tag value
 */
fs::Tag JC_Array::computeTag() const noexcept {
  fs::Tag out;

  out.len = this->array[0];

  for (uint8_t idx = 0; idx < out.len; idx++) {
    out.value[idx] = this->array[idx + 1];
  }

  return out;
}

/**
 * Get the array entry size.
 *
 * @param[type] the type of each array's entry.
 * @return the array entry's size.
 */
const uint16_t JC_Array::getEntrySize(const jc_array_type type) {
  switch (type) {
  case jc_array_type::JAVA_ARRAY_T_BYTE:
    return sizeof(jbyte_t);

  case jc_array_type::JAVA_ARRAY_T_BOOLEAN:
    return sizeof(jbool_t);

  case jc_array_type::JAVA_ARRAY_T_SHORT:
    return sizeof(jshort_t);

#ifdef JCVM_INT_SUPPORTED

  case jc_array_type::JAVA_ARRAY_T_INT:
    return sizeof(jint_t);

#endif /* JCVM_INT_SUPPORTED */

  case jc_array_type::JAVA_ARRAY_T_REFERENCE:
    return sizeof(jref_t);
  }

  throw Exceptions::SecurityException;
}

/**
 * Get the array entry size.
 *
 * @return the array entry's size.
 */
uint16_t JC_Array::getEntrySize() const {
  return this->getEntrySize(this->getType());
}

/**
 * Get array type.
 *
 * @return array type.
 */
jc_array_type JC_Array::getType() const noexcept { return this->type; }

/**
 * Get array reference type.
 *
 * @return array reference type.
 */
jc_cp_offset_t JC_Array::getReferenceType() const
#ifndef JCVM_SECURE_HEAP_ACCESS
    noexcept
#endif /* JCVM_SECURE_HEAP_ACCESS */
{
#ifdef JCVM_SECURE_HEAP_ACCESS

  if (this->type != jc_array_type::JAVA_ARRAY_T_REFERENCE) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */

  return this->reference_type;
}

/**
 * Get array size.
 *
 * @return array size.
 */
uint16_t JC_Array::size() const {
  uint32_t length = 0;

  if (this->isTransientArray()) {
    fs::Tag tag = this->computeTag();

    length = this->array.size() - tag.len - sizeof(tag.len);
  } else if (this->isPersistent()) {
    fs::Tag tag = this->computeTag();

    if (fs_length(tag.value, tag.len, &length)) {
      throw Exceptions::IOException;
    }
  } else {
    length = this->array.size();
  }

  return (uint16_t)(length / JC_Array::getEntrySize(this->type));
}

/**
 * Fetch a byte or a boolean element from an array.
 *
 * @param[index] index of the byte or boolean element to return
 * @return the indexed byte or boolean element.
 */
jbyte_t JC_Array::getByteEntry(const uint16_t index)
#ifndef JCVM_SECURE_HEAP_ACCESS
    const noexcept(noexcept(std::declval<JCVMArray<uint8_t> &>()[index]))
#endif /* !JCVM_SECURE_HEAP_ACCESS */
{
#ifdef JCVM_SECURE_HEAP_ACCESS

  switch (type) {
  case jc_array_type::JAVA_ARRAY_T_BYTE:
  case jc_array_type::JAVA_ARRAY_T_BOOLEAN:
    // OK
    break;

  default:
    // NOK
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */

  if (this->isPersistent()) {
    auto tag = this->computeTag();

    if (this->isTransientArray()) {
      const uint16_t offset = (uint16_t)(index * sizeof(jbyte_t));

      return this->array[tag.len + sizeof(tag.len) + offset];
    } else {
      return FlashMemory_Handler::getPersistentField_Array_Byte(tag, index
#ifdef JCVM_SECURE_HEAP_ACCESS
                                                                ,
                                                                this->getOwner()
#endif /* JCVM_SECURE_HEAP_ACESS */
      );
    }
  } else {
    const uint16_t offset = (uint16_t)(index * sizeof(jbyte_t));

    return this->array[offset];
  }
}

/**
 * Fetch a short element from an array.
 *
 * @param[index] index of the short element to return
 * @return the indexed short element.
 */
jshort_t JC_Array::getShortEntry(const uint16_t index)
#ifndef JCVM_SECURE_HEAP_ACCESS
    const noexcept(noexcept(std::declval<JCVMArray<uint8_t> &>()[index]))
#endif /* !JCVM_SECURE_HEAP_ACCESS */
{
#ifdef JCVM_SECURE_HEAP_ACCESS

  if (this->type != jc_array_type::JAVA_ARRAY_T_SHORT) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */

  if (this->isPersistent()) {
    auto tag = this->computeTag();

    if (this->isTransientArray()) {
      const uint16_t offset = (uint16_t)(index * sizeof(jshort_t));

      return BYTES_TO_SHORT(
          this->array[tag.len + sizeof(tag.len) + offset],
          this->array[tag.len + sizeof(tag.len) + offset + 1]);
    } else {
      return FlashMemory_Handler::getPersistentField_Array_Short(
          tag, index
#ifdef JCVM_SECURE_HEAP_ACCESS
          ,
          this->getOwner()
#endif /* JCVM_SECURE_HEAP_ACESS */
      );
    }
  } else {
    const uint16_t offset = (uint16_t)(index * sizeof(jshort_t));

    return BYTES_TO_SHORT(this->array[offset],
                          this->array[(uint16_t)(offset + 1)]);
  }
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Fetch a int element from an array.
 *
 * @param[index] index of the int element to return
 * @return the indexed int element.
 */
jint_t JC_Array::getIntEntry(const uint16_t index)
#ifndef JCVM_SECURE_HEAP_ACCESS
    const noexcept(noexcept(std::declval<JCVMArray<uint8_t> &>()[index]))
#endif /* !JCVM_SECURE_HEAP_ACCESS */
{

#ifdef JCVM_SECURE_HEAP_ACCESS

  if (this->type != jc_array_type::JAVA_ARRAY_T_INT) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */

  if (this->isPersistent()) {
    auto tag = this->computeTag();

    if (this->isTransientArray()) {
      const uint16_t offset = (uint16_t)(index * sizeof(jint_t));

      return BYTES_TO_INT(this->array[tag.len + sizeof(tag.len) + offset],
                          this->array[tag.len + sizeof(tag.len) + offset + 1],
                          this->array[tag.len + sizeof(tag.len) + offset + 2],
                          this->array[tag.len + sizeof(tag.len) + offset + 3]);
    } else {
      return FlashMemory_Handler::getPersistentField_Array_Int(tag, index
#ifdef JCVM_SECURE_HEAP_ACCESS
                                                               ,
                                                               this->getOwner()
#endif /* JCVM_SECURE_HEAP_ACESS */
      );
    }
  } else {
    const uint16_t offset = (uint16_t)(index * sizeof(jint_t));

    return BYTES_TO_INT(this->array[offset], this->array[offset + 1],
                        this->array[offset + 2], this->array[offset + 3]);
  }
}
#endif /* JCVM_INT_SUPPORTED */

/**
 * Fetch a reference element from an array.
 *
 * @param[index] index of the reference element to return
 * @return the indexed reference element.
 */
jref_t JC_Array::getReferenceEntry(const uint16_t index)
#ifndef JCVM_SECURE_HEAP_ACCESS
    noexcept(noexcept(std::declval<JCVMArray<uint8_t> &>()[index]))
#endif /* !JCVM_SECURE_HEAP_ACCESS */
{

#ifdef JCVM_SECURE_HEAP_ACCESS

  if (this->type != jc_array_type::JAVA_ARRAY_T_REFERENCE) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */

  if (this->isPersistent()) {
    auto tag = this->computeTag();

    if (this->isTransientArray()) {
      const uint16_t offset = (uint16_t)(index * sizeof(jref_t));

      return BYTES_TO_SHORT(
          this->array[tag.len + sizeof(tag.len) + offset],
          this->array[tag.len + sizeof(tag.len) + offset + 1]);
    } else {
      return FlashMemory_Handler::getPersistentField_Array_Reference(
          tag, index, this->getOwner());
    }
  } else {
    const uint16_t offset = (uint16_t)(index * sizeof(jref_t));
    return jref_t(BYTES_TO_SHORT(this->array[offset], this->array[offset + 1]));
  }
}

/**
 * Write a byte or a boolean element from an array.
 *
 * @param[index] index of the element to set.
 * @param[value] the new value
 */
void JC_Array::setByteEntry(const uint16_t index, const jbyte_t value)
#ifndef JCVM_SECURE_HEAP_ACCESS
    noexcept(noexcept(std::declval<JCVMArray<uint8_t> &>()[index]))
#endif /* !JCVM_SECURE_HEAP_ACCESS */
{
#ifdef JCVM_SECURE_HEAP_ACCESS

  switch (type) {
  case jc_array_type::JAVA_ARRAY_T_BOOLEAN:
  case jc_array_type::JAVA_ARRAY_T_BYTE:
    // OK
    break;

  default:
    // NOK
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */

  if (this->isPersistent()) {
    auto tag = this->computeTag();

    if (this->isTransientArray()) {
      const uint16_t offset = (uint16_t)(index * sizeof(jbyte_t));

      this->array[tag.len + sizeof(tag.len) + offset] = value;
    } else {
      FlashMemory_Handler::setPersistentField_Array_Byte(tag, index, value
#ifdef JCVM_SECURE_HEAP_ACCESS
                                                         ,
                                                         this->getOwner()
#endif /* JCVM_SECURE_HEAP_ACESS */
      );
    }
  } else {
    const uint16_t offset = (uint16_t)(index * sizeof(jbyte_t));

    this->array[offset] = value;
  }
}

/**
 * Write a byte or a boolean element from an array.
 *
 * @param[index] index of the element to set.
 * @param[value] the new value
 */
void JC_Array::setShortEntry(const uint16_t index, const jshort_t value)
#ifndef JCVM_SECURE_HEAP_ACCESS
    noexcept(noexcept(std::declval<JCVMArray<uint8_t> &>()[index]))
#endif /* !JCVM_SECURE_HEAP_ACCESS */
{
#ifdef JCVM_SECURE_HEAP_ACCESS

  if (this->type != jc_array_type::JAVA_ARRAY_T_SHORT) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */

  if (this->isPersistent()) {
    auto tag = this->computeTag();

    if (this->isTransientArray()) {
      const uint16_t offset = (uint16_t)(index * sizeof(jshort_t));

      this->array[tag.len + sizeof(tag.len) + offset] = HIGH_BYTE_SHORT(value);
      this->array[tag.len + sizeof(tag.len) + offset + 1] =
          LOW_BYTE_SHORT(value);
    } else {
      FlashMemory_Handler::setPersistentField_Array_Short(tag, index, value
#ifdef JCVM_SECURE_HEAP_ACCESS
                                                          ,
                                                          this->getOwner()
#endif /* JCVM_SECURE_HEAP_ACESS */
      );
    }
  } else {
    const uint16_t offset = (uint16_t)(index * sizeof(jshort_t));

    this->array[offset] = HIGH_BYTE_SHORT(value);
    this->array[offset + 1] = LOW_BYTE_SHORT(value);
  }
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Write a byte or a boolean element from an array.
 *
 * @param[index] index of the element to set.
 * @param[value] the new value
 */
void JC_Array::setIntEntry(const uint16_t index, const jint_t value)
#ifndef JCVM_SECURE_HEAP_ACCESS
    noexcept(noexcept(std::declval<JCVMArray<uint8_t> &>()[index]))
#endif /* !JCVM_SECURE_HEAP_ACCESS */
{
#ifdef JCVM_SECURE_HEAP_ACCESS

  if (this->type != jc_array_type::JAVA_ARRAY_T_INT) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */

  if (this->isPersistent()) {
    auto tag = this->computeTag();

    if (this->isTransientArray()) {
      const uint16_t offset = (uint16_t)(index * sizeof(jint_t));

      this->array[tag.len + sizeof(tag.len) + offset] =
          HIGH_BYTE_SHORT(INT_2_MSSHORTS(value));
      this->array[tag.len + sizeof(tag.len) + offset + 1] =
          LOW_BYTE_SHORT(INT_2_MSSHORTS(value));
      this->array[tag.len + sizeof(tag.len) + offset + 2] =
          HIGH_BYTE_SHORT(INT_2_LSSHORTS(value));
      this->array[tag.len + sizeof(tag.len) + offset + 3] =
          LOW_BYTE_SHORT(INT_2_LSSHORTS(value));
    } else {
      FlashMemory_Handler::setPersistentField_Array_Int(tag, index, value
#ifdef JCVM_SECURE_HEAP_ACCESS
                                                        ,
                                                        this->getOwner()
#endif /* JCVM_SECURE_HEAP_ACESS */
      );
    }
  } else {
    const uint16_t offset = (uint16_t)(index * sizeof(jint_t));

    this->array[offset] = HIGH_BYTE_SHORT(INT_2_MSSHORTS(value));
    this->array[offset + 1] = LOW_BYTE_SHORT(INT_2_MSSHORTS(value));
    this->array[offset + 2] = HIGH_BYTE_SHORT(INT_2_LSSHORTS(value));
    this->array[offset + 3] = LOW_BYTE_SHORT(INT_2_LSSHORTS(value));
  }
}
#endif /* JCVM_INT_SUPPORTED */

/**
 * Write a byte or a boolean element from an array.
 *
 * @param[index] index of the element to set.
 * @param[value] the new value
 */
void JC_Array::setReferenceEntry(const uint16_t index, const jref_t value
#ifdef JCVM_FIREWALL_CHECKS
                                 ,
                                 Context &context
#endif /* JCVM_FIREWALL_CHECKS */
                                 )
#if !defined(JCVM_SECURE_HEAP_ACCESS) && !defined(JCVM_FIREWALL_CHECKS)
    noexcept(noexcept(std::declval<JCVMArray<uint8_t> &>()[index]))
#endif /* !JCVM_SECURE_HEAP_ACCESS && !JCVM_FIREWALL_CHECKS */
{
#ifdef JCVM_SECURE_HEAP_ACCESS

  if (this->type != jc_array_type::JAVA_ARRAY_T_REFERENCE) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */

#ifdef JCVM_FIREWALL_CHECKS
  // Check if types are compatible.
  Heap &heap = context.getHeap();
  auto current_package = context.getCurrentPackage();
  ConstantPool_Handler cp_handler(current_package);
  Class_Handler class_handler(current_package);

  if (value.isNullPointer()) {
    // NULL pointer: nothing to do.
    ;
  } else if (value.isInstance()) {
    auto instanceref_to_add = heap.getInstance(value);

    auto classref_in = std::make_pair<uint32_t, const uint8_t *>(
        instanceref_to_add->getPackageID(),
        reinterpret_cast<const uint8_t *>(
            ConstantPool_Handler(instanceref_to_add->getPackageID())
                .getClassFromClassIndex(instanceref_to_add->getClassIndex())));
    auto classref_out = cp_handler.getClassRef(this->reference_type);

    if (class_handler.docheckcast(
            classref_in, cp_handler.resolveClassref(classref_out)) == FALSE) {
      throw Exceptions::ArrayStoreException;
    }
  } else {
    auto arrayref_to_add = heap.getArray(value);

    /// It is an array reference.
    switch (arrayref_to_add->getType()) {
    case jc_array_type::JAVA_ARRAY_T_BOOLEAN:
    case jc_array_type::JAVA_ARRAY_T_BYTE:
    case jc_array_type::JAVA_ARRAY_T_SHORT:
#ifdef JCVM_INT_SUPPORTED
    case jc_array_type::JAVA_ARRAY_T_INT:
#endif /* JCVM_INT_SUPPORTED */
    {
      auto array_reference_classref =
          cp_handler.getClassRef(this->reference_type);
      auto array_reference_class =
          cp_handler.classref2class(array_reference_classref);

      if (!(array_reference_class.second->isObjectClass())) {
        throw Exceptions::ArrayStoreException;
      }

      break;
    }

    case jc_array_type::JAVA_ARRAY_T_REFERENCE: {

      auto classref_in =
          cp_handler.getClassRef(arrayref_to_add->getReferenceType());
      auto classref_out = cp_handler.getClassRef(this->reference_type);

      if (class_handler.docheckcast(cp_handler.resolveClassref(classref_in),
                                    cp_handler.resolveClassref(classref_out)) ==
          FALSE) {
        throw Exceptions::ArrayStoreException;
      }
    }

    break;

    default:
      throw Exceptions::SecurityException;
    }
  }

#endif /* JCVM_FIREWALL_CHECKS */

  if (this->isPersistent()) {
    auto tag = this->computeTag();

    if (this->isTransientArray()) {
      const uint16_t offset = (uint16_t)(index * sizeof(jref_t));

      this->array[tag.len + sizeof(tag.len) + offset] =
          HIGH_BYTE_SHORT(value.compact());
      this->array[tag.len + sizeof(tag.len) + offset + 1] =
          LOW_BYTE_SHORT(value.compact());
    } else {
      FlashMemory_Handler::setPersistentField_Array_Reference(tag, index, value,
                                                              this->getOwner());
    }
  } else {

    const uint16_t offset = (uint16_t)(index * sizeof(jref_t));

    this->array[offset] = HIGH_BYTE_SHORT(value.compact());
    this->array[(uint16_t)(offset + 1)] = LOW_BYTE_SHORT(value.compact());
  }
}

/*
 * Get a const pointer to array data
 *
 * @return Const pointer to array data
 */
const uint8_t *JC_Array::getData() const {

  if (this->isPersistent()) {
    auto tag = this->computeTag();

    if (this->isTransientArray()) {
      return &(this->array.data()[tag.len + sizeof(tag.len)]);
    } else {
      throw Exceptions::RuntimeException;
    }
  }

  return static_cast<const uint8_t *>(this->array.data());
}

/*
 * Is a transient array?
 *
 */
const bool JC_Array::isTransientArray() const noexcept {
  return this->isTransient;
}

/*
 * Get clear event
 *
 */
const ClearEvent JC_Array::getClearEvent() const noexcept {
  return this->clear;
}

} // namespace jcvm
