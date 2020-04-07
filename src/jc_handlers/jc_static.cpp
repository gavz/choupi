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

#include "jc_static.hpp"
#include "../exceptions.hpp"
#include "../heap.hpp"
#include "flashmemory.hpp"

namespace jcvm {

/**
 * Get static byte value.
 *
 * @param[index] static byte index in the current package.
 * @return the static byte value.
 */
jbyte_t Static_Handler::getPersistentByte(const uint16_t index) const {
  fs::Tag tag = FlashMemory_Handler::getStaticFieldTag(
      this->package.getPackageID(), index);
  return FlashMemory_Handler::getPersistentField_Byte(tag);
}

/**
 * Get static short value.
 *
 * @param[index] static short index in the current package.
 * @return the static short value.
 */
jshort_t Static_Handler::getPersistentShort(const uint16_t index) const {
  fs::Tag tag = FlashMemory_Handler::getStaticFieldTag(
      this->package.getPackageID(), index);
  return FlashMemory_Handler::getPersistentField_Short(tag);
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Get static integer value.
 *
 * @param[index] static integer index in the current package.
 * @return the static integer value.
 */
jint_t Static_Handler::getPersistentInt(const uint16_t index) const {
  fs::Tag tag = FlashMemory_Handler::getStaticFieldTag(
      this->package.getPackageID(), index);
  return FlashMemory_Handler::getPersistentField_Int(tag);
}
#endif /* JCVM_INT_SUPPORTED */

/*
 * Read static serialized instance or array.
 *
 * @param[index] static index in the current package.
 * @return static serialized instance or array.
 */
jref_t Static_Handler::getPersistentRef(const uint16_t index,
                                        Heap &heap) const {
  fs::Tag tag = FlashMemory_Handler::getStaticFieldTag(
      this->package.getPackageID(), index);

  return FlashMemory_Handler::getPersistentField_Reference(tag, heap);
}

/**
 * Set static byte value.
 *
 * @param[index] static byte index in the current package.
 * @param[value] new the static byte value.
 */
void Static_Handler::setPersistentByte(const uint16_t index,
                                       const jbyte_t value) {
  fs::Tag tag = FlashMemory_Handler::getStaticFieldTag(
      this->package.getPackageID(), index);

  FlashMemory_Handler::setPersistentField_Byte(tag, value);
}

/**
 * Set static short value.
 *
 * @param[index] static short index in the current package.
 * @param[value] new the static short value.
 */
void Static_Handler::setPersistentShort(const uint16_t index,
                                        const jshort_t value) {
  fs::Tag tag = FlashMemory_Handler::getStaticFieldTag(
      this->package.getPackageID(), index);

  FlashMemory_Handler::setPersistentField_Short(tag, value);
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Set static integer value.
 *
 * @param[index] static integer index in the current package.
 * @param[value] new the static integer value.
 */
void Static_Handler::setPersistentInt(const uint16_t index,
                                      const jint_t value) {
  fs::Tag tag = FlashMemory_Handler::getStaticFieldTag(
      this->package.getPackageID(), index);

  JCVMArray<jbyte_t> data(sizeof(jint_t));
  data[0] = HIGH_BYTE_SHORT(INT_2_MSSHORTS(value));
  data[1] = LOW_BYTE_SHORT(INT_2_MSSHORTS(value));
  data[2] = HIGH_BYTE_SHORT(INT_2_LSSHORTS(value));
  data[3] = LOW_BYTE_SHORT(INT_2_LSSHORTS(value));

  FlashMemory_Handler::setPersistentField_Int(tag, value);
}
#endif /* JCVM_INT_SUPPORTED */

} // namespace jcvm
