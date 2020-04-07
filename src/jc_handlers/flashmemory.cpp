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

#include "flashmemory.hpp"
#include "../exceptions.hpp"
#include "../heap.hpp"
#include "../jc_types/jc_array.hpp"
#include "../jc_types/jc_field.hpp"
#include "../jc_types/jc_instance.hpp"
#include "../jc_utils.hpp"
#include "ffi.h"

#include <cassert>

namespace jcvm {

/// Get packages array length
static constexpr uint16_t getPackagesArrayLength() {
  static_assert((JCVM_MAX_PACKAGES % 8) == 0,
                "JCVM_MAX_PACKAGES value must be a multiple of 8.");
  return JCVM_MAX_PACKAGES / 8;
}

/**
 * Read data from tag
 *
 * @param[tag] Associated tag value.
 * @return data associated to the tag.
 */
std::pair<uint32_t, uint8_t *>
FlashMemory_Handler::getDataFromTag(const fs::Tag &tag) {
  uint32_t data_length = 0;

  if (fs_length(&(tag.value[0]), tag.len, &data_length)) {
    throw Exceptions::IOException;
  }

  if (data_length == 0) {
    throw Exceptions::IOException;
  }

  uint8_t *data = new uint8_t[data_length];

  if (data == nullptr) {
    throw Exceptions::IOException;
  }

  if (fs_read(&(tag.value[0]), tag.len, data, data_length)) {
    throw Exceptions::IOException;
  }

  return std::make_pair(data_length, data);
}

/**
 * Write persistant instance header
 *
 * @param[tag] Associated tag value.
 * param[package] instance package ID
 * @param[class_index] instance class index
 */
void FlashMemory_Handler::writeInstanceHeader(
    const fs::Tag &tag, const jpackage_ID_t package,
    const jclass_index_t class_index) {
  static_assert(sizeof(jpackage_ID_t) == sizeof(uint8_t),
                "jpackage_ID_t type size must be same as uint8_t");
  static_assert(sizeof(jclass_index_t) == sizeof(uint16_t),
                "jclass_index_t type size must be same as uint16_t");

  uint8_t data[] = {FieldType::FIELD_TYPE_OBJECT, package,
                    HIGH_BYTE_SHORT(class_index), LOW_BYTE_SHORT(class_index)};

  if (fs_write(tag.value, tag.len, data, (sizeof(data) / sizeof(data[0])))) {
    throw Exceptions::IOException;
  }
}

/**
 * Write persistant array data
 *
 * @param[tag] Associated tag value.
 * @param[array_type] array type to write
 * @param[data] array data
 */
void FlashMemory_Handler::writeArray(const fs::Tag &tag, const FieldType type,
                                     JC_Array &array, Heap &heap) {

  static_assert(sizeof(decltype(array.getReferenceType())) == sizeof(uint16_t),
                "japplet_ID_t should be encoded on 2-byte.");

  uint8_t *data = nullptr;
  uint16_t header = sizeof(FieldType) + sizeof(array.size());
  uint16_t array_size = 0;

  if (array.isTransientArray()) {
    header += sizeof(ClearEvent);
  }

  if ((type == FieldType::FIELD_TYPE_ARRAY_OBJECT) ||
      (type == FieldType::FIELD_TYPE_TRANSIENT_ARRAY_OBJECT)) {
    header += sizeof(array.getReferenceType());
  }

  if (array.isTransientArray() ||
      (type == FieldType::FIELD_TYPE_ARRAY_OBJECT)) {
    array_size = header;
  } else {
    array_size = header + array.size() * array.getEntrySize();
  }

  data = new uint8_t[array_size];

  uint8_t pos = 0;

  data[pos++] = type;
  data[pos++] = HIGH_BYTE_SHORT(array.size());
  data[pos++] = LOW_BYTE_SHORT(array.size());

  if (array.isTransientArray()) {
    data[pos++] = array.getClearEvent();
  }

  if ((type == FieldType::FIELD_TYPE_ARRAY_OBJECT) ||
      (type == FieldType::FIELD_TYPE_TRANSIENT_ARRAY_OBJECT)) {
    data[pos++] = HIGH_BYTE_SHORT(array.getReferenceType());
    data[pos++] = LOW_BYTE_SHORT(array.getReferenceType());
  }

  if (type == FieldType::FIELD_TYPE_ARRAY_OBJECT) {
    for (decltype(array.size()) idx = 0; idx < array.size(); idx++) {
      if ((tag.len + sizeof(idx)) >=
          (sizeof(tag.value) / sizeof(tag.value[0]))) {
        throw Exceptions::IOException;
      }

      fs::Tag new_tag = FlashMemory_Handler::computeTag(tag, idx);

      jref_t objectref = array.getReferenceEntry(idx);

      if (objectref.isArray()) {
        auto array = heap.getArray(objectref);
        FlashMemory_Handler::setPersistentField_Array(new_tag, *array, heap);
      } else { // Is an instance
        auto instance = heap.getInstance(objectref);
        FlashMemory_Handler::setPersistentField_Instance(new_tag, *instance,
                                                         heap);
      }
    }
  } else {
    if (array.isTransientArray()) {
      // Do not copy data
    } else {
      for (uint16_t index = 0; index < (array_size - header); index++) {
        data[index + header] = array.getData()[index];
      }
    }
  }

  // How to write data?
  if (type == FieldType::FIELD_TYPE_ARRAY_OBJECT) {
    /*
     * If transient:
     * 0            8        24            32                40
     * +------------+---------+-------------+-----------------+
     * | Field Type | nbEntry | Clean Event | Reference Type  |
     * +------------+---------+-------------+-----------------+
     *
     *  else:
     * 0            8        24                40
     * +------------+---------+-----------------+
     * | Field Type | nbEntry | Reference Type  |
     * +------------+---------+-----------------+
     */
  } else {
    /*
     * If transient:
     * 0            8        24
     * +------------+---------+-------------+--------+--------+-----
     * | Field Type | nbEntry | Clean Event | Word 1 | Word 2 | ...
     * +------------+---------+-------------+--------+--------+-----
     *
     *  else:
     * 0            8        24
     * +------------+---------+--------+--------+------
     * | Field Type | nbEntry | Word 1 | Word 2 | ...
     * +------------+---------+--------+--------+------
     */
  }

  if (fs_write(tag.value, tag.len, data, array_size)) {
    throw Exceptions::IOException;
  }

  if (data != nullptr) {
    delete[] data;
  }
}
///
///        Compute tag to access to persistant data
fs::Tag FlashMemory_Handler::computeTag(const fs::Tag &tag,
                                        const uint16_t index)
#ifndef JCVM_SECURE_HEAP_ACCESS
    noexcept
#endif /* JCVM_SECURE_HEAP_ACCESS */
{
  fs::Tag new_tag;

  new_tag.len = tag.len + sizeof(index);

#ifdef JCVM_SECURE_HEAP_ACCESS

  if (new_tag.len > (sizeof(new_tag.value) / sizeof(new_tag.value[0]))) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */

  for (uint8_t idx = 0; idx < tag.len; idx++) {
    new_tag.value[idx] = tag.value[idx];
  }

  new_tag.value[tag.len] = LOW_BYTE_SHORT(index);
  new_tag.value[tag.len + 1] = LOW_BYTE_SHORT(index);

  return new_tag;
}

/**
 * Read data in place from tag
 *
 * @param[tag] Associated tag value.
 * @return data associated to the tag.
 */
std::pair<uint32_t, const uint8_t *>
FlashMemory_Handler::getDataInPlaceFromTag(const fs::Tag &tag) {
  const uint8_t *data = nullptr;
  uint32_t data_length;

  if (fs_read_inplace(&(tag.value[0]), tag.len, &data, &data_length)) {
    throw Exceptions::IOException;
  }

  if (data_length == 0) {
    throw Exceptions::IOException;
  }

  if (data == nullptr) {
    throw Exceptions::IOException;
  }

  return std::make_pair(data_length, data);
}

/*
 * Write data from tag
 *
 * @param[tag] Associated tag value
 * @param[length] data length to write
 * @param[data] data to write
 */
void FlashMemory_Handler::setDataFromTag(const fs::Tag &tag, uint32_t length,
                                         const uint8_t data[]) {

  if (fs_write(&(tag.value[0]), tag.len, data, length)) {
    throw Exceptions::IOException;
  }
}

/**
 * Make tag for package list.
 *
 * @return package list's tag.
 */
const fs::Tag FlashMemory_Handler::getPackagesListTag() noexcept {
  fs::Tag tag;
  path_package_list(&(tag.value), &(tag.len));
  return tag;
}

/**
 * Make tag for a CAP file.
 *
 * @return CAP file's tag.
 */
const fs::Tag
FlashMemory_Handler::getCapTag(const jpackage_ID_t package) noexcept {
  fs::Tag tag;
  path_cap(package, &(tag.value), &(tag.len));
  return tag;
}

/**
 * Make tag for a static field.
 *
 * @param[package] the associated package ID
 * @param[static_id] the static field index to read
 *
 * @return static field's tag.
 */
const fs::Tag
FlashMemory_Handler::getStaticFieldTag(const jpackage_ID_t package,
                                       const uint8_t static_id) noexcept {
  fs::Tag tag;
  path_static(package, static_id, &(tag.value), &(tag.len));
  return tag;
}

/**
 * Make tag for an applet field.
 *
 * @param[applet_owner] applet owner ID.
 * @param[package] the associated package ID
 * @param[claz] the associated class ID
 * @param[field] the associated field number
 *
 * @return applet field's tag.
 */
const fs::Tag FlashMemory_Handler::getPersistentFieldTag(
    const japplet_ID_t applet_owner, const jpackage_ID_t package,
    const jclass_index_t claz, const uint8_t field) noexcept {
  fs::Tag tag;
  path_applet_field(applet_owner, package, claz, field, &(tag.value),
                    &(tag.len));
  return tag;
}

/**
 * Get a static field from a tag. This field should be a serialized instance or
 * array
 *
 * @param[tag] the data tag value to read.
 *
 * @return the read static field value.
 */
jref_t FlashMemory_Handler::getPersistentField_Reference(const fs::Tag &tag,
                                                         Heap &heap) {
  uint32_t length = 0;
  const uint8_t *data = nullptr;

  try {
    auto [length_tmp, data_tmp] =
        FlashMemory_Handler::getDataInPlaceFromTag(tag);
    length = length_tmp;
    data = data_tmp;
  } catch (Exceptions e) {
    jref_t out;
    out.setAsArray(false);
    out.setOffset(0);
    return out;
  }

  FieldType type = static_cast<FieldType>(data[0]);
  uint16_t size = BYTES_TO_SHORT(data[2], data[1]);

  switch (type) {
  case FieldType::FIELD_TYPE_ARRAY_BYTE: {
    return heap.addArray(JC_Array(heap, JAVA_ARRAY_T_BYTE, 0, tag, false,
                                  ClearEvent::None, size));
  }

  case FieldType::FIELD_TYPE_ARRAY_BOOLEAN: {
    return heap.addArray(JC_Array(heap, JAVA_ARRAY_T_BOOLEAN, 0, tag, false,
                                  ClearEvent::None, size));
  }

  case FieldType::FIELD_TYPE_ARRAY_SHORT: {
    return heap.addArray(JC_Array(heap, JAVA_ARRAY_T_SHORT, 0, tag, false,
                                  ClearEvent::None, size));
  }

#ifdef JCVM_INT_SUPPORTED

  case FieldType::FIELD_TYPE_ARRAY_INT: {
    return heap.addArray(JC_Array(heap, JAVA_ARRAY_T_INT, 0, tag, false,
                                  ClearEvent::None, size));
  }

#endif /* JCVM_INT_SUPPORTED */

  case FieldType::FIELD_TYPE_ARRAY_OBJECT: {
    jc_cp_offset_t cp_offset =
        static_cast<jc_cp_offset_t>(BYTES_TO_SHORT(data[3], data[4]));
    return heap.addArray(JC_Array(heap, JAVA_ARRAY_T_REFERENCE, cp_offset, tag,
                                  false, ClearEvent::None, size));
  }

  case FieldType::FIELD_TYPE_OBJECT: {
    static_assert(sizeof(jclass_index_t) == sizeof(uint16_t),
                  "jclass_index_t type should be equals to uint16_t");

    jpackage_ID_t package = static_cast<jpackage_ID_t>(data[1]);
    jclass_index_t claz =
        static_cast<jclass_index_t>(BYTES_TO_SHORT(data[2], data[3]));
    return heap.addInstance(JC_Instance(heap, package, claz, tag));
  }

  case FieldType::FIELD_TYPE_TRANSIENT_ARRAY_BYTE: {
    ClearEvent event = static_cast<ClearEvent>(data[3]);
    return heap.addArray(
        JC_Array(heap, JAVA_ARRAY_T_BYTE, 0, tag, true, event, size));
  }

  case FieldType::FIELD_TYPE_TRANSIENT_ARRAY_BOOLEAN: {
    ClearEvent event = static_cast<ClearEvent>(data[3]);
    return heap.addArray(
        JC_Array(heap, JAVA_ARRAY_T_BOOLEAN, 0, tag, true, event, size));
  }

  case FieldType::FIELD_TYPE_TRANSIENT_ARRAY_SHORT: {
    ClearEvent event = static_cast<ClearEvent>(data[3]);
    return heap.addArray(
        JC_Array(heap, JAVA_ARRAY_T_SHORT, 0, tag, true, event, size));
  }

#ifdef JCVM_INT_SUPPORTED

  case FieldType::FIELD_TYPE_TRANSIENT_ARRAY_INT: {
    ClearEvent event = static_cast<ClearEvent>(data[3]);
    return heap.addArray(
        JC_Array(heap, JAVA_ARRAY_T_INT, 0, tag, true, event, size));
  }

#endif /* JCVM_INT_SUPPORTED */

  case FieldType::FIELD_TYPE_TRANSIENT_ARRAY_OBJECT: {
    ClearEvent event = static_cast<ClearEvent>(data[3]);
    jc_cp_offset_t cp_offset =
        static_cast<jc_cp_offset_t>(BYTES_TO_SHORT(data[4], data[5]));

    return heap.addArray(JC_Array(heap, JAVA_ARRAY_T_REFERENCE, cp_offset, tag,
                                  true, event, size));
  }

  case FieldType::FIELD_TYPE_UNINITIALIZED: {
    jref_t out;
    out.setAsArray(false);
    out.setOffset(0);
    return out;
  }

  default:
    throw Exceptions::IOException;
  }
}

/*
 * Write static array field from tag
 *
 */
void FlashMemory_Handler::setPersistentField_Array(const fs::Tag &tag,
                                                   JC_Array &array,
                                                   Heap &heap) {
  FieldType type;

  switch (array.getType()) {
  case JAVA_ARRAY_T_BOOLEAN:
    if (array.isTransientArray()) {
      type = FieldType::FIELD_TYPE_TRANSIENT_ARRAY_BOOLEAN;
    } else {
      type = FieldType::FIELD_TYPE_ARRAY_BOOLEAN;
    }

    break;

  case JAVA_ARRAY_T_BYTE:
    if (array.isTransientArray()) {
      type = FieldType::FIELD_TYPE_TRANSIENT_ARRAY_BYTE;
    } else {
      type = FieldType::FIELD_TYPE_ARRAY_BYTE;
    }

    break;

  case JAVA_ARRAY_T_SHORT:
    if (array.isTransientArray()) {
      type = FieldType::FIELD_TYPE_TRANSIENT_ARRAY_SHORT;
    } else {
      type = FieldType::FIELD_TYPE_ARRAY_SHORT;
    }

    break;

#ifdef JCVM_INT_SUPPORTED

  case JAVA_ARRAY_T_INT:
    if (array.isTransientArray()) {
      type = FieldType::FIELD_TYPE_TRANSIENT_ARRAY_INT;
    } else {
      type = FieldType::FIELD_TYPE_ARRAY_INT;
    }

    break;
#endif /* JCVM_INT_SUPPORTED */

  case JAVA_ARRAY_T_REFERENCE:
    if (array.isTransientArray()) {
      type = FieldType::FIELD_TYPE_TRANSIENT_ARRAY_OBJECT;
    } else {
      type = FieldType::FIELD_TYPE_ARRAY_OBJECT;
    }

    break;

  default:
    throw Exceptions::SecurityException;
  }

  FlashMemory_Handler::writeArray(tag, type, array, heap);
}

/*
 * Write static instance field from tag
 *
 * @param[tag] associated tag
 * @param[instance] instance to write
 * @param[heap] associated heap
 */
void FlashMemory_Handler::setPersistentField_Instance(
    const fs::Tag &tag, const JC_Instance &instance, Heap &heap) {
  auto fields = instance.getFields();

  if (fields == nullptr) {
    // TODO: It's a normal behavior?
    throw Exceptions::SecurityException;
  }

  FlashMemory_Handler::writeInstanceHeader(tag, instance.getPackageID(),
                                           instance.getClassIndex());

  for (uint16_t idx = 0; idx < fields->size(); idx++) {

    fs::Tag field_tag = FlashMemory_Handler::computeTag(tag, idx);

    jc_field_t field = fields->at(idx);

    switch (field.type) {
    case FieldType::FIELD_TYPE_BYTE:
    case FieldType::FIELD_TYPE_BOOLEAN: {
      const uint8_t data[] = {field.type, static_cast<uint8_t>(field.value)};

      if (fs_write(field_tag.value, field_tag.len, data,
                   sizeof(jbyte_t) + sizeof(uint8_t))) {
        throw Exceptions::IOException;
      }

      break;
    }

    case FieldType::FIELD_TYPE_SHORT: {
      const uint8_t data[] = {
          field.type, static_cast<uint8_t>(HIGH_BYTE_SHORT(field.value)),
          static_cast<uint8_t>(LOW_BYTE_SHORT(field.value))};

      if (fs_write(field_tag.value, field_tag.len, data,
                   sizeof(jshort_t) + sizeof(uint8_t))) {
        throw Exceptions::IOException;
      }

      break;
    }

#ifdef JCVM_INT_SUPPORTED

    case FieldType::FIELD_TYPE_INT: {
      jc_field_t field_low = fields->at(++idx);
      jint_t value = SHORTS_TO_INT(static_cast<jshort_t>(field.value),
                                   static_cast<jshort_t>(field_low.value));
      const uint8_t data[] = {
          field.type,
          static_cast<uint8_t>(HIGH_BYTE_SHORT(INT_2_MSSHORTS(value))),
          static_cast<uint8_t>(LOW_BYTE_SHORT(INT_2_MSSHORTS(value))),
          static_cast<uint8_t>(HIGH_BYTE_SHORT(INT_2_LSSHORTS(value))),
          static_cast<uint8_t>(LOW_BYTE_SHORT(INT_2_LSSHORTS(value))),
      };

      if (fs_write(field_tag.value, field_tag.len, data,
                   sizeof(jint_t) + sizeof(uint8_t))) {
        throw Exceptions::IOException;
      }

      break;
    }

#endif /* JCVM_INT_SUPPORTED */

    case FieldType::FIELD_TYPE_OBJECT: {
      jref_t objectref = static_cast<jref_t>(field.value);

      if (objectref.isArray()) {
        throw Exceptions::SecurityException;
      }

      auto field_instance = heap.getInstance(objectref);
      FlashMemory_Handler::setPersistentField_Instance(field_tag,
                                                       *field_instance, heap);
      break;
    }

    case FieldType::FIELD_TYPE_ARRAY_BYTE:
    case FieldType::FIELD_TYPE_ARRAY_BOOLEAN:
    case FieldType::FIELD_TYPE_ARRAY_SHORT:
#ifdef JCVM_INT_SUPPORTED
    case FieldType::FIELD_TYPE_ARRAY_INT:
#endif /* JCVM_INT_SUPPORTED */
    case FieldType::FIELD_TYPE_ARRAY_OBJECT:
    case FieldType::FIELD_TYPE_TRANSIENT_ARRAY_BYTE:
    case FieldType::FIELD_TYPE_TRANSIENT_ARRAY_BOOLEAN:
    case FieldType::FIELD_TYPE_TRANSIENT_ARRAY_SHORT:
#ifdef JCVM_INT_SUPPORTED
    case FieldType::FIELD_TYPE_TRANSIENT_ARRAY_INT:
#endif /* JCVM_INT_SUPPORTED */
    case FieldType::FIELD_TYPE_TRANSIENT_ARRAY_OBJECT: {
      jref_t arrayref = static_cast<jref_t>(field.value);

      if (!arrayref.isArray()) { // Is an array?
        throw Exceptions::SecurityException;
      }

      auto array = heap.getArray(arrayref);
      FlashMemory_Handler::writeArray(field_tag, field.type, *array, heap);

      break;
    }

    case FieldType::FIELD_TYPE_UNINITIALIZED:
    default:
      throw Exceptions::SecurityException;
    }
  }
}

/**
 * Get byte data store in flash memory.
 *
 * @param[tag] associated tag
 *
 * @return the requested field
 */
const jbyte_t FlashMemory_Handler::getPersistentField_Byte(const fs::Tag &tag) {
  auto [length, data] = FlashMemory_Handler::getDataFromTag(tag);

#ifdef JCVM_ARRAY_SIZE_CHECK

  if (length != sizeof(jbyte_t) + 1) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_ARRAY_SIZE_CHECK */

#ifdef JCVM_SECURE_HEAP_ACCESS
  FieldType type = static_cast<FieldType>(data[0]);

  switch (type) {
  case FieldType::FIELD_TYPE_BOOLEAN:
  case FieldType::FIELD_TYPE_BYTE:
    // OK
    break;

  default:
    // NOK
    throw SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */

  return static_cast<jbyte_t>(data[1]);
}

/**
 * Set byte data store in flash memory.
 *
 * @param[tag] associated tag
 * @param[value] value to write
 */
void FlashMemory_Handler::setPersistentField_Byte(const fs::Tag &tag,
                                                  const jbyte_t value) {
  static_assert(sizeof(jbyte_t) == sizeof(uint8_t),
                "jbyte_t and uint8_t are not compatible!");
  const uint8_t data[] = {FieldType::FIELD_TYPE_BYTE,
                          static_cast<const uint8_t>(value)};
  uint32_t length = sizeof(data) / sizeof((data)[0]);
  FlashMemory_Handler::setDataFromTag(tag, length, data);
}

/**
 * Get short data store in flash memory.
 *
 * @param[tag] associated tag
 *
 *  @return the requested field
 */
const jshort_t
FlashMemory_Handler::getPersistentField_Short(const fs::Tag &tag) {
  auto [length, data] = FlashMemory_Handler::getDataFromTag(tag);

#ifdef JCVM_ARRAY_SIZE_CHECK

  if (length != (sizeof(jshort_t) + 1)) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_ARRAY_SIZE_CHECK */

#ifdef JCVM_SECURE_HEAP_ACCESS
  FieldType type = static_cast<FieldType>(data[0]);

  if (type != FieldType::FIELD_TYPE_SHORT) {
    // NOK
    throw SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */

  return BYTES_TO_SHORT(data[1], data[2]);
}

/**
 * Set short data store in flash memory.
 *
 * @param[tag] associated tag
 * @param[value] value to write
 */
void FlashMemory_Handler::setPersistentField_Short(const fs::Tag &tag,
                                                   const jshort_t value) {
  static_assert(sizeof(jshort_t) == 2 * sizeof(uint8_t),
                "jshort_t is not encoded on 2 uint8_t!");

  const uint8_t data[] = {
      FieldType::FIELD_TYPE_SHORT,
      HIGH_BYTE_SHORT(value),
      LOW_BYTE_SHORT(value),
  };

  uint32_t length = sizeof(data) / sizeof((data)[0]);
  FlashMemory_Handler::setDataFromTag(tag, length, data);
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Get short data store in flash memory.
 *
 * @param[tag] associated tag
 *
 *  @return the requested field
 */
const jint_t FlashMemory_Handler::getPersistentField_Int(const fs::Tag &tag) {
  auto [length, data] = FlashMemory_Handler::getDataFromTag(tag);

#ifdef JCVM_ARRAY_SIZE_CHECK

  if (length != (sizeof(jint_t) + 1)) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_ARRAY_SIZE_CHECK */

#ifdef JCVM_SECURE_HEAP_ACCESS
  FieldType type = static_cast<FieldType>(data[0]);

  if (type != FieldType::FIELD_TYPE_INT) {
    // NOK
    throw SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */

  return BYTES_TO_INT(data[1], data[2], data[3], data[4]);
}

/**
 * Set short data store in flash memory.
 *
 * @param[tag] associated tag
 * @param[value] value to write
 */
void FlashMemory_Handler::setPersistentField_Int(const fs::Tag &tag,
                                                 const jint_t value) {
  static_assert(sizeof(jshort_t) == 2 * sizeof(uint8_t),
                "jint_t is not encoded on 2 uint8_t!");
  const uint8_t data[] = {
      FieldType::FIELD_TYPE_INT,
      HIGH_BYTE_SHORT(INT_2_MSSHORTS(value)),
      LOW_BYTE_SHORT(INT_2_MSSHORTS(value)),
      HIGH_BYTE_SHORT(INT_2_LSSHORTS(value)),
      LOW_BYTE_SHORT(INT_2_LSSHORTS(value)),
  };

  uint32_t length = sizeof(data) / sizeof((data)[0]);
  FlashMemory_Handler::setDataFromTag(tag, length, data);
}
#endif /* JCVM_INT_SUPPORTED */

/**
 * Get array data store in flash memory.
 *
 * @param[tag] Associated tag value.
 *
 * @return the requested field as an array.
 */
std::shared_ptr<JC_Array>
FlashMemory_Handler::getPersistentField_Array(const fs::Tag &tag, Heap &heap) {
  auto [length, array_flash] = FlashMemory_Handler::getDataInPlaceFromTag(tag);

  uint16_t pos = 0;

  FieldType type = static_cast<FieldType>(array_flash[pos++]);
  uint16_t size = BYTES_TO_SHORT(array_flash[pos], array_flash[pos + 1]);
  pos += 2;
  ClearEvent event = ClearEvent::None;
  jc_cp_offset_t reference_type = 0;

  jc_array_type array_type;
  bool isTransient = false;

  switch (type) {
  case FIELD_TYPE_ARRAY_BOOLEAN: {
    array_type = JAVA_ARRAY_T_BOOLEAN;
    isTransient = false;
    event = static_cast<ClearEvent>(array_flash[pos]);
    break;
  }

  case FIELD_TYPE_TRANSIENT_ARRAY_BOOLEAN: {
    array_type = JAVA_ARRAY_T_BOOLEAN;
    isTransient = true;
    event = static_cast<ClearEvent>(array_flash[pos]);
    break;
  }

  case FIELD_TYPE_ARRAY_BYTE: {
    array_type = JAVA_ARRAY_T_BYTE;
    isTransient = false;
    break;
  }

  case FIELD_TYPE_TRANSIENT_ARRAY_BYTE: {
    array_type = JAVA_ARRAY_T_BYTE;
    isTransient = true;
    event = static_cast<ClearEvent>(array_flash[pos]);
    break;
  }

  case FIELD_TYPE_ARRAY_SHORT: {
    array_type = JAVA_ARRAY_T_SHORT;
    isTransient = false;
    break;
  }

  case FIELD_TYPE_TRANSIENT_ARRAY_SHORT: {
    array_type = JAVA_ARRAY_T_SHORT;
    isTransient = true;
    event = static_cast<ClearEvent>(array_flash[pos]);
    break;
  }

#ifdef JCVM_INT_SUPPORTED

  case FIELD_TYPE_ARRAY_INT: {
    array_type = JAVA_ARRAY_T_INT;
    isTransient = false;
    break;
  }

  case FIELD_TYPE_TRANSIENT_ARRAY_INT: {
    array_type = JAVA_ARRAY_T_INT;
    isTransient = true;
    event = static_cast<ClearEvent>(array_flash[pos]);
    break;
  }

#endif /* JCVM_INT_SUPPORTED */

  case FIELD_TYPE_ARRAY_OBJECT: {
    array_type = JAVA_ARRAY_T_REFERENCE;
    isTransient = false;
    reference_type = BYTES_TO_SHORT(array_flash[pos], array_flash[pos + 1]);
    // pos += 2;
    break;
  }

  case FIELD_TYPE_TRANSIENT_ARRAY_OBJECT: {
    array_type = JAVA_ARRAY_T_REFERENCE;
    isTransient = true;
    event = static_cast<ClearEvent>(array_flash[pos++]);
    reference_type = BYTES_TO_SHORT(array_flash[pos], array_flash[pos + 1]);
    // pos += 2;
    break;
  }

  default:
    throw Exceptions::SecurityException;
  }

  return std::make_shared<JC_Array>(heap, array_type, reference_type, tag,
                                    isTransient, event, size);
}

/*
 * Get array data store value in flash memory at a specific index.
 *
 * @param[tag] Associated tag value.
 * @param[index] data index
 *
 * @return indexed data value
 */
const jbyte_t
FlashMemory_Handler::getPersistentField_Array_Byte(const fs::Tag &tag,
                                                   const uint16_t index
#ifdef JCVM_SECURE_HEAP_ACCESS
                                                   ,
                                                   Heap &heap
#endif /* JCVM_SECURE_HEAP_ACCESS */
) {
  uint8_t value;

#ifdef JCVM_SECURE_HEAP_ACCESS
  auto array = FlashMemory_Handler::getPersistentField_Array(tag, heap);

  if (array->size() <= index) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */

  if (fs_read_1b_at(&(tag.value[0]), tag.len, index, &value)) {
    throw Exceptions::IOException;
  }

  return static_cast<const jbyte_t>(value);
}

/*
 * Set array data store value in flash memory at a specific index.
 *
 * @param[tag] Associated tag value.
 * @param[index] data index
 * @param[value] value to write
 */
void FlashMemory_Handler::setPersistentField_Array_Byte(const fs::Tag &tag,
                                                        const uint16_t index,
                                                        const jbyte_t value
#ifdef JCVM_SECURE_HEAP_ACCESS
                                                        ,
                                                        Heap &heap
#endif /* JCVM_SECURE_HEAP_ACCESS */
) {
#ifdef JCVM_SECURE_HEAP_ACCESS
  auto array = FlashMemory_Handler::getPersistentField_Array(tag, heap);

  if (array->size() <= index) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */

  if (fs_write_1b_at(&(tag.value[0]), tag.len, index, value)) {
    throw Exceptions::IOException;
  }
}

/*
 * Get array data store value in flash memory at a specific index.
 *
 * @param[tag] Associated tag value.
 * @param[index] data index
 *
 * @return indexed data value
 */
const jshort_t
FlashMemory_Handler::getPersistentField_Array_Short(const fs::Tag &tag,
                                                    const uint16_t index
#ifdef JCVM_SECURE_HEAP_ACCESS
                                                    ,
                                                    Heap &heap
#endif /* JCVM_SECURE_HEAP_ACCESS */
) {
  uint16_t value;

#ifdef JCVM_SECURE_HEAP_ACCESS
  auto array = FlashMemory_Handler::getPersistentField_Array(tag, heap);

  if (array->size() <= index) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */

  if (fs_read_2b_at(&(tag.value[0]), tag.len, index, &value)) {
    throw Exceptions::IOException;
  }

  return static_cast<const jshort_t>(value);
}

/*
 * Set array data store value in flash memory at a specific index.
 *
 * @param[tag] Associated tag value.
 * @param[index] data index
 * @param[value] value to write
 */
void FlashMemory_Handler::setPersistentField_Array_Short(const fs::Tag &tag,
                                                         const uint16_t index,
                                                         const jshort_t value
#ifdef JCVM_SECURE_HEAP_ACCESS
                                                         ,
                                                         Heap &heap
#endif /* JCVM_SECURE_HEAP_ACCESS */
) {
#ifdef JCVM_SECURE_HEAP_ACCESS
  auto array = FlashMemory_Handler::getPersistentField_Array(tag, heap);

  if (array->size() <= index) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */

  if (fs_write_2b_at(&(tag.value[0]), tag.len, index, value)) {
    throw Exceptions::IOException;
  }
}

#ifdef JCVM_INT_SUPPORTED

/*
 * Get array data store value in flash memory at a specific index.
 *
 * @param[tag] Associated tag value.
 * @param[index] data index
 *
 * @return indexed data value
 */
const jint_t
FlashMemory_Handler::getPersistentField_Array_Int(const fs::Tag &tag,
                                                  const uint16_t index
#ifdef JCVM_SECURE_HEAP_ACCESS
                                                  ,
                                                  Heap &heap
#endif /* JCVM_SECURE_HEAP_ACCESS */
) {
  uint32_t value;

#ifdef JCVM_SECURE_HEAP_ACCESS
  auto array = FlashMemory_Handler::getPersistentField_Array(tag, heap);

  if (array->size() <= index) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */

  if (fs_read_4b_at(&(tag.value[0]), tag.len, index, &value)) {
    throw Exceptions::IOException;
  }

  return static_cast<const jint_t>(value);
}

/*
 * Set array data store value in flash memory at a specific index.
 *
 * @param[tag] Associated tag value.
 * @param[index] data index
 * @param[value] value to write
 */
void FlashMemory_Handler::setPersistentField_Array_Int(const fs::Tag &tag,
                                                       const uint16_t index,
                                                       const jint_t value
#ifdef JCVM_SECURE_HEAP_ACCESS
                                                       ,
                                                       Heap &heap
#endif /* JCVM_SECURE_HEAP_ACCESS */
) {
#ifdef JCVM_SECURE_HEAP_ACCESS
  auto array = FlashMemory_Handler::getPersistentField_Array(tag, heap);

  if (array->size() <= index) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */

  if (fs_write_4b_at(&(tag.value[0]), tag.len, index, value)) {
    throw Exceptions::IOException;
  }
}
#endif /* JCVM_INT_SUPPORTED */

/*
 * Get array data store value in flash memory at a specific index.
 *
 * @param[tag] Associated tag value.
 * @param[index] data index
 *
 * @return indexed data value
 */
const jref_t FlashMemory_Handler::getPersistentField_Array_Reference(
    const fs::Tag &tag, const uint16_t index, Heap &heap) {

#ifdef JCVM_SECURE_HEAP_ACCESS
  {
    auto array = FlashMemory_Handler::getPersistentField_Array(tag, heap);

    if (array->isTransientArray()) {
      throw Exceptions::SecurityException;
    }

    if (array->getType() != JAVA_ARRAY_T_REFERENCE) {
      throw Exceptions::SecurityException;
    }
  }
#endif /* JCVM_SECURE_HEAP_ACCESS */

  if ((tag.len + 2) > (sizeof(tag.value) / sizeof(tag.value[0]))) {
    throw Exceptions::IOException;
  }

  fs::Tag field_tag = FlashMemory_Handler::computeTag(tag, index);
  return FlashMemory_Handler::getPersistentField_Reference(tag, heap);
}

/*
 * Set array data store value in flash memory at a specific index.
 *
 * @param[tag] Associated tag value.
 * @param[index] data index
 * @param[value] value to write
 */
void FlashMemory_Handler::setPersistentField_Array_Reference(
    const fs::Tag &tag, const uint16_t index, const jref_t value, Heap &heap) {

#ifdef JCVM_SECURE_HEAP_ACCESS
  auto array = FlashMemory_Handler::getPersistentField_Array(tag, heap);

  if (array->size() <= index) {
    throw Exceptions::SecurityException;
  }

#endif /* JCVM_SECURE_HEAP_ACCESS */

  fs::Tag field_tag = FlashMemory_Handler::computeTag(tag, index);
  field_tag.len = tag.len;

  for (uint8_t idx = 0; idx < tag.len; idx++) {
    field_tag.value[idx] = tag.value[idx];
  }

  if (value.isArray()) {
    auto array = heap.getArray(value);
    return FlashMemory_Handler::setPersistentField_Array(tag, *array, heap);
  } else {
    auto instance = heap.getInstance(value);
    return FlashMemory_Handler::setPersistentField_Instance(tag, *instance,
                                                            heap);
  }
}

/**
 * Get a pointer to the Packages array
 *
 * @return a pointer to the packages array.
 */
std::shared_ptr<const uint8_t> FlashMemory_Handler::getPackagesArray() {
  auto &tag = FlashMemory_Handler::getPackagesListTag();
  auto packages_array = FlashMemory_Handler::getDataInPlaceFromTag(tag);

  if (packages_array.first != getPackagesArrayLength()) {
    throw Exceptions::SecurityException;
  }

  return std::shared_ptr<const uint8_t>(packages_array.second);
}

/**
 * Enable a Java Card Package in the Java Card Package Array in the flash
 * memory.
 *
 * @param[id] The Package ID to enable.
 */
void FlashMemory_Handler::enablePackage(const jpackage_ID_t id) {
  auto &tag = FlashMemory_Handler::getPackagesListTag();
  uint8_t packages_byte;

  // Reading the value to update
  if (fs_read_1b_at(tag.value, tag.len, (id / 8), &packages_byte)) {
    throw Exceptions::IOException;
  }

  packages_byte |= (1 << (id % 8));

  // Writing the updated value
  if (fs_write_1b_at(tag.value, tag.len, (id / 8), packages_byte)) {
    throw Exceptions::IOException;
  }
}

/**
 * Disable a Java Card Package in the Java Card Package Array in the flash
 * memory.
 *
 * @param[id] The Package ID to disable.
 */
void FlashMemory_Handler::disablePackage(const jpackage_ID_t id) {
  auto &tag = FlashMemory_Handler::getPackagesListTag();
  uint8_t packages_byte;

  // Reading the value to update
  if (fs_read_1b_at(tag.value, tag.len, (id / 8), &packages_byte)) {
    throw Exceptions::IOException;
  }

  packages_byte &= ~(1 << (id % 8));

  // Writing the updated value
  if (fs_write_1b_at(tag.value, tag.len, (id / 8), packages_byte)) {
    throw Exceptions::IOException;
  }
}

/**
 * Is there package exist?
 *
 * @param[id] The Package ID to disable.
 */
bool FlashMemory_Handler::isPackageExist(const jpackage_ID_t id) {
  auto &tag = FlashMemory_Handler::getPackagesListTag();
  uint8_t packages_byte;

  // Reading the value to update
  if (fs_read_1b_at(tag.value, tag.len, (id / 8), &packages_byte)) {
    throw Exceptions::IOException;
  }

  return packages_byte & (1 << (id % 8));
}

/**
 * Get a CAP file from a package ID.
 *
 * @param[packageID] Package ID where the CAP file is located.
 * @return the read CAP file.
 */
JC_Cap FlashMemory_Handler::getCap(const jpackage_ID_t packageID) {
  auto &tag = FlashMemory_Handler::getCapTag(packageID);
  auto cap = getDataInPlaceFromTag(tag);

  return JC_Cap(cap.first, cap.second);
}

} // namespace jcvm
