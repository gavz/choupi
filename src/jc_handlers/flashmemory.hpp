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

#ifndef _FLASHMEMORY_HPP
#define _FLASHMEMORY_HPP

#include "../heap.hpp"
#include "../jc_config.h"
#include "../jc_types/jc_field.hpp"
#include "../jc_types/jref_t.hpp"

#include "jc_cap.hpp"

#include <memory>
#include <utility>

namespace jcvm {

class JC_Array;    // Forward declaration of JC_Array
class JC_Instance; // Forward declaration of JC_Instance
class Heap;        // Forward declaration of Heap

namespace fs {

#define TAG_MAX_LENGTH 32

struct Tag {
  uint8_t len = 0;
  uint8_t value[TAG_MAX_LENGTH] = {0};
};

} // namespace fs

class FlashMemory_Handler {
private:
  /// Read data from tag
  static std::pair<uint32_t, uint8_t *> getDataFromTag(const fs::Tag &tag);
  /// Read data in place from tag
  static std::pair<uint32_t, const uint8_t *>
  getDataInPlaceFromTag(const fs::Tag &tag);
  /// Write data from tag
  static void setDataFromTag(const fs::Tag &tag, uint32_t length,
                             const uint8_t data[]);

  /// Write instance meta data
  static void writeInstanceHeader(const fs::Tag &tag,
                                  const jpackage_ID_t package,
                                  const jclass_index_t class_index);

  /// Write array data
  static void writeArray(const fs::Tag &tag, const FieldType type,
                         JC_Array &array, Heap &heap);

public:
  ///  Compute tag to access to persistant data
  static fs::Tag computeTag(const fs::Tag &tag, const uint16_t index)
#ifndef JCVM_SECURE_HEAP_ACCESS
      noexcept
#endif /* JCVM_SECURE_HEAP_ACCESS */
      ;

  /// Make tag for a packages list.
  static const fs::Tag getPackagesListTag() noexcept;
  /// Make tag for a CAP file.
  static const fs::Tag getCapTag(const jpackage_ID_t package) noexcept;
  /// Make tag for a static field.
  static const fs::Tag getStaticFieldTag(const jpackage_ID_t package,
                                         const uint8_t static_id) noexcept;
  /// Make tag for an applet field.
  static const fs::Tag getPersistentFieldTag(const japplet_ID_t applet_owner,
                                             const jpackage_ID_t package,
                                             const jclass_index_t claz,
                                             const uint8_t field) noexcept;

  /// Read byte from an address.
  static jbyte_t getByteFromAddr(const uint8_t *const address) noexcept;

  /// Get array data store in flash memory.
  static std::shared_ptr<JC_Array> getPersistentField_Array(const fs::Tag &tag,
                                                            Heap &heap);
  /// Get array data store in flash memory.
  static void setPersistentField_Array(const fs::Tag &tag, JC_Array &array,
                                       Heap &heap);
  /// Set instance data store in flash memory.
  static void setPersistentField_Instance(const fs::Tag &tag,
                                          const JC_Instance &instance,
                                          Heap &heap);

  /// Get byte data store in flash memory.
  static const jbyte_t getPersistentField_Byte(const fs::Tag &tag);
  /// Set byte data store in flash memory.
  static void setPersistentField_Byte(const fs::Tag &tag, const jbyte_t value);
  /// Get short data store in flash memory.
  static const jshort_t getPersistentField_Short(const fs::Tag &tag);
  /// Set short data store in flash memory.
  static void setPersistentField_Short(const fs::Tag &tag,
                                       const jshort_t value);
#ifdef JCVM_INT_SUPPORTED
  /// Get int data store in flash memory.
  static const jint_t getPersistentField_Int(const fs::Tag &tag);
  /// Set int data store in flash memory.
  static void setPersistentField_Int(const fs::Tag &tag, jint_t value);
#endif /* JCVM_INT_SUPPORTED */
  /// Get int data store in flash memory.
  static jref_t getPersistentField_Reference(const fs::Tag &tag, Heap &heap);

  /// Get array data store value in flash memory at a specific index.
  static const jbyte_t getPersistentField_Array_Byte(const fs::Tag &tag,
                                                     const uint16_t index
#ifdef JCVM_SECURE_HEAP_ACCESS
                                                     ,
                                                     Heap &heap
#endif /* JCVM_SECURE_HEAP_ACCESS */
  );
  /// Set array data store in flash memory at a specific index.
  static void setPersistentField_Array_Byte(const fs::Tag &tag,
                                            const uint16_t index,
                                            const jbyte_t value
#ifdef JCVM_SECURE_HEAP_ACCESS
                                            ,
                                            Heap &heap
#endif /* JCVM_SECURE_HEAP_ACCESS */
  );
  /// Get array data store in flash memory at a specific index.
  static const jshort_t getPersistentField_Array_Short(const fs::Tag &tag,
                                                       const uint16_t index
#ifdef JCVM_SECURE_HEAP_ACCESS
                                                       ,
                                                       Heap &heap
#endif /* JCVM_SECURE_HEAP_ACCESS */
  );
  /// Set array data store in flash memory at a specific index.
  static void setPersistentField_Array_Short(const fs::Tag &tag,
                                             const uint16_t index,
                                             const jshort_t value
#ifdef JCVM_SECURE_HEAP_ACCESS
                                             ,
                                             Heap &heap
#endif /* JCVM_SECURE_HEAP_ACCESS */
  );
#ifdef JCVM_INT_SUPPORTED
  /// Get array data store in flash memory at a specific index.
  static const jint_t getPersistentField_Array_Int(const fs::Tag &tag,
                                                   const uint16_t index
#ifdef JCVM_SECURE_HEAP_ACCESS
                                                   ,
                                                   Heap &heap
#endif /* JCVM_SECURE_HEAP_ACCESS */
  );
  /// Set array data store in flash memory at a specific index.
  static void setPersistentField_Array_Int(const fs::Tag &tag,
                                           const uint16_t index,
                                           const jint_t value
#ifdef JCVM_SECURE_HEAP_ACCESS
                                           ,
                                           Heap &heap
#endif /* JCVM_SECURE_HEAP_ACCESS */
  );
#endif /* JCVM_INT_SUPPORTED */
  /// Get array data store in flash memory at a specific index.
  static const jref_t getPersistentField_Array_Reference(const fs::Tag &tag,
                                                         const uint16_t index,
                                                         Heap &heap);
  /// Set array data store in flash memory at a specific index.
  static void setPersistentField_Array_Reference(const fs::Tag &tag,
                                                 const uint16_t index,
                                                 const jref_t value,
                                                 Heap &heap);

  /// Get a pointer to the Packages array.
  static std::shared_ptr<const uint8_t> getPackagesArray();
  /// Enable a package
  static void enablePackage(const jpackage_ID_t id);
  /// Disable a package.
  static void disablePackage(const jpackage_ID_t id);
  /// Is there package exist?
  static bool isPackageExist(const jpackage_ID_t id);
  /// Get a CAP file from a package ID.
  static JC_Cap getCap(const jpackage_ID_t packageID);
};

} // namespace jcvm

#endif /* _FLASHMEMORY_HPP */
