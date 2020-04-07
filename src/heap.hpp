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

#ifndef _HEAP_HPP
#define _HEAP_HPP

#include "exceptions.hpp"
#include "jc_config.h"
#include "jc_handlers/flashmemory.hpp"
#include "jc_types/jc_array_type.hpp"
#include "jc_types/jc_instance.hpp"
#include "jc_types/jref_t.hpp"
#include "jc_utils.hpp"
#include "jcvm_types/list.hpp"
#include "types.hpp"

#include <memory>

namespace jcvm {

class JC_Array; // Forward declaration of JC_Array

class Heap {
private:
  ///
  const japplet_ID_t owner;

  /// List of array in the heap.
  List<std::shared_ptr<JC_Array>> arrays;
  /// List of instance in the heap.
  List<std::shared_ptr<JC_Instance>> instances;

  /// Getting field reference from an instance reference.
  // jc_field_t &getFieldFromInstanceRef(jref_t objectref, uint16_t index);

public:
  /// Default constructor.
  Heap(const japplet_ID_t owner) noexcept;

  /// Getting the applet ID owner
  japplet_ID_t getOwner() const;

  /// Adding new array in the transient heap.
  jref_t addArray(const uint16_t nb_entry, const jc_array_type type);
  /// Adding new reference array in the transient heap.
  jref_t addArray(const uint16_t nb_entry, const jc_array_type type,
                  const jc_cp_offset_t array_reference_type);
  /// Adding an array in in the transient heap.
  jref_t addArray(JC_Array array);
  /// Adding new instance in the transient heap.
  jref_t addInstance(const jpackage_ID_t packageID,
                     const jclass_index_t instantiated_class);
  /// Adding an instance in in the transient heap.
  jref_t addInstance(JC_Instance intance);

  /// Getting array from the transient heap.
  std::shared_ptr<JC_Array> getArray(const jref_t objectref)
#ifndef JCVM_SECURE_HEAP_ACCESS
      noexcept
#endif /* JCVM_SECURE_HEAP_ACCESS */
      ;

  /// Getting instance from the transient heap.
  std::shared_ptr<JC_Instance> getInstance(const jref_t objectref)
#ifndef JCVM_SECURE_HEAP_ACCESS
      noexcept
#endif /* JCVM_SECURE_HEAP_ACCESS */
      ;
};

} // namespace jcvm

#endif /* _HEAP_HPP */
