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

#include "jc_instance.hpp"
#include "../jc_handlers/flashmemory.hpp"
#include "../jc_handlers/jc_class.hpp"
#include "../jc_handlers/jc_cp.hpp"
#include "../jc_utils.hpp"
#include "jc_array.hpp"

namespace jcvm {

/**
 * Default constructor.
 *
 * @param[owner] owner
 * @param[package_owner] package owner
 * @param[instantiated_class] Constant Pool token to the instantiated class.
 */
JC_Instance::JC_Instance(Heap &owner, const Package &package_owner,
                         const jc_cp_offset_t instantiated_class) noexcept
    : JC_Object(owner, false) {
  ConstantPool_Handler cp(package_owner);
  std::pair<jpackage_ID_t, jclass_index_t> pair =
      cp.getClassInformation(instantiated_class);

  this->packageID = pair.first;
  this->claz = pair.second;

  Class_Handler class_handler(this->packageID);
  uint16_t fields_size = class_handler.getInstanceFieldsSize(this->claz);
  this->fields = new JCVMArray<jc_field_t>(fields_size);
}

/**
 * Default constructor.
 *
 * @param[owner] owner
 * @param[packageID] class package ID
 * @param[claz] class index
 */
JC_Instance::JC_Instance(Heap &owner, const jpackage_ID_t packageID,
                         const jclass_index_t claz) noexcept
    : JC_Object(owner, false), packageID(packageID), claz(claz) {
  Class_Handler class_handler(this->packageID);
  uint16_t fields_size = class_handler.getInstanceFieldsSize(this->claz);
  this->fields = new JCVMArray<jc_field_t>(fields_size);
};

/**
 * Default constructor.
 *
 * @param[owner] owner
 * @param[packageID] class package ID
 * @param[claz] class index
 * @param[tag] persistant associated tag value
 * @param[isStatic] is a static instance?
 */
JC_Instance::JC_Instance(Heap &owner, const jpackage_ID_t packageID,
                         const jclass_index_t claz_index,
                         const fs::Tag &tag) noexcept
    : JC_Object(owner, true), packageID(packageID), claz(claz) {

  jc_field_t field_tag[tag.len];

  for (uint8_t idx = 0; idx < tag.len; idx++) {
    field_tag[idx].value = tag.value[idx];
  }

  this->fields = new JCVMArray<jc_field_t>(tag.len, field_tag);
}

/*
 * Default destructor
 */
JC_Instance::~JC_Instance() noexcept {
  if (this->fields != nullptr) {
    delete this->fields;
  }
}

/**
 * Recompute instance Tag
 *
 * @return original instance tag
 */
fs::Tag JC_Instance::recomputeOriginalTag() const noexcept {
  fs::Tag tag;

  tag.len = this->fields->size();

  for (decltype(this->fields->size()) idx; idx < this->fields->size(); idx++) {
    tag.value[idx] = static_cast<uint8_t>(this->fields->at(idx).value);
  }

  return tag;
}

/*
 * Get package ID
 *
 * @return Class package ID
 */
jpackage_ID_t JC_Instance::getPackageID() const noexcept {
  return this->packageID;
}

/*
 * Get class index
 *
 * @return Class index
 */
jclass_index_t JC_Instance::getClassIndex() const noexcept {
  return this->claz;
}

/*
 * Set package ID
 *
 * @param[packageID] new package ID
 */
void JC_Instance::setPackageID(const jpackage_ID_t packageID) noexcept {
  this->packageID = packageID;
}

/*
 * Set class index
 *
 * @param[class_index] new class index
 */
void JC_Instance::setClassIndex(const jclass_index_t class_index) noexcept {
  this->claz = class_index;
}

/**
 * Fetch byte or boolean from object.
 *
 * @param[index] index of the instance field to fetch.
 * @return The fetched instance field value.
 */
const jbyte_t JC_Instance::getField_Byte(const uint16_t index) {
  if (this->isPersistent()) {
    fs::Tag tag =
        FlashMemory_Handler::computeTag(this->recomputeOriginalTag(), index);

    return FlashMemory_Handler::getPersistentField_Byte(tag);
  } else {

#ifdef JCVM_TYPED_HEAP
    // TODO: the instance data value type should be verified.
#endif /* JCVM_TYPED_HEAP */

    return (jbyte_t)(this->fields->at(index).value);
  }
}

/**
 * Fetch short from object.
 *
 * @param[index] index of the instance field to fetch.
 * @return The fetched instance field value.
 */
const jshort_t JC_Instance::getField_Short(const uint16_t index) {
  if (this->isPersistent()) {
    fs::Tag tag =
        FlashMemory_Handler::computeTag(this->recomputeOriginalTag(), index);

    return FlashMemory_Handler::getPersistentField_Short(tag);
  } else {

#ifdef JCVM_TYPED_HEAP
    // TODO: the instance data value type should be verified.
#endif /* JCVM_TYPED_HEAP */

    return (jshort_t)(this->fields->at(index).value);
  }
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Fetch int from object.
 *
 * @param[index] index of the instance field to fetch.
 * @return The fetched instance field value.
 */
const jint_t JC_Instance::getField_Int(const uint16_t index) {
  if (this->isPersistent()) {
    fs::Tag tag =
        FlashMemory_Handler::computeTag(this->recomputeOriginalTag(), index);

    return FlashMemory_Handler::getPersistentField_Int(tag);
  } else {

    const jword_t field_high_part = this->fields->at(index).value;
    const jword_t field_low_part =
        this->fields->at((uint16_t)(index + 1)).value;

#ifdef JCVM_TYPED_HEAP
    // TODO: the instance data value type should be verified.
#endif /* JCVM_TYPED_HEAP */

    return (jint_t)(SHORTS_TO_INT(field_high_part, field_low_part));
  }
}

#endif /* JCVM_INT_SUPPORTED */
/**
 * Fetch reference from object.
 *
 * @param[index] index of the instance field to fetch.
 * @return The fetched instance field value.
 */
const jref_t JC_Instance::getField_Reference(const uint16_t index) {
  if (this->isPersistent()) {
    fs::Tag tag =
        FlashMemory_Handler::computeTag(this->recomputeOriginalTag(), index);

    FlashMemory_Handler::getPersistentField_Reference(tag, this->getOwner());
  } else {

#ifdef JCVM_TYPED_HEAP
    // TODO: the instance data value type should be verified.
#endif /* JCVM_TYPED_HEAP */

    return jref_t(this->fields->at(index).value);
  }
}

/**
 * Set byte or boolean field from object.
 *
 * @param[index] index of the instance field to set.
 * @param[value] new value.
 */
void JC_Instance::setField_Byte(uint16_t index, jbyte_t value) {
  if (this->isPersistent()) {
    fs::Tag tag =
        FlashMemory_Handler::computeTag(this->recomputeOriginalTag(), index);

    FlashMemory_Handler::setPersistentField_Byte(tag, value);
  } else {

#ifdef JCVM_TYPED_HEAP
    // TODO: the instance data value type should be saved.
#endif /* JCVM_TYPED_HEAP */

    this->fields->at(index).value = (jword_t)(BYTE_TO_WORD(value));
  }
}

/**
 * Set short field from object.
 *
 * @param[index] index of the instance field to set.
 * @param[value] new value.
 */
void JC_Instance::setField_Short(const uint16_t index, const jshort_t value) {
  if (this->isPersistent()) {
    fs::Tag tag =
        FlashMemory_Handler::computeTag(this->recomputeOriginalTag(), index);

    FlashMemory_Handler::setPersistentField_Short(tag, value);
  } else {

#ifdef JCVM_TYPED_HEAP
    // TODO: the instance data value type should be saved.
#endif /* JCVM_TYPED_HEAP */

    this->fields->at(index).value = (jword_t)(value);
  }
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Set int field from object.
 *
 * @param[index] index of the instance field to set.
 * @param[value] new value.
 */
void JC_Instance::setField_Int(const uint16_t index, const jint_t value) {
  if (this->isPersistent()) {
    fs::Tag tag =
        FlashMemory_Handler::computeTag(this->recomputeOriginalTag(), index);

    FlashMemory_Handler::setPersistentField_Int(tag, value);
  } else {

#ifdef JCVM_TYPED_HEAP
    // TODO: the instance data value type should be saved.
#endif /* JCVM_TYPED_HEAP */

    this->fields->at(index).value = (jword_t)(INT_2_MSSHORTS(value));
    this->fields->at((uint16_t)(index + 1)).value =
        (jword_t)(INT_2_LSSHORTS(value));
  }
}

#endif /* JCVM_INT_SUPPORTED */

/**
 * Set reference field from object.
 *
 * @param[index] index of the instance field to set.
 * @param[value] new value.
 */
void JC_Instance::setField_Reference(const uint16_t index, const jref_t ref) {
  if (this->isPersistent()) {
    fs::Tag tag =
        FlashMemory_Handler::computeTag(this->recomputeOriginalTag(), index);

    if (ref.isArray()) {
      auto array = this->getOwner().getArray(ref);
      FlashMemory_Handler::setPersistentField_Array(tag, *array,
                                                    this->getOwner());
    } else {
      auto instance = this->getOwner().getInstance(ref);
      FlashMemory_Handler::setPersistentField_Instance(tag, *instance,
                                                       this->getOwner());
    }
  } else {

#ifdef JCVM_TYPED_HEAP
    // TODO: the instance data value type should be saved.
#endif /* JCVM_TYPED_HEAP */

    this->fields->at(index).value = (jword_t)(ref.compact());
  }
}

/**
 * Get the number of instance field.
 *
 * @return the number of instance field.
 */
auto JC_Instance::getNumberOfFields() const noexcept
    -> decltype(fields->size()) {
  if (this->isPersistent()) {
    Class_Handler class_handler(this->packageID);
    return class_handler.getInstanceFieldsSize(this->claz);
  } else {
    return this->fields->size();
  }
}

///  Get fields arrays
/**
 * Get the number of instance field.
 *
 * @return the number of instance field.
 */
auto JC_Instance::getFields() const noexcept -> decltype(fields) {
  if (this->isPersistent()) {
    throw Exceptions::NotYetImplemented;
  } else {
    return this->fields;
  }
}

} // namespace jcvm
