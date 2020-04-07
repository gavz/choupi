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

#ifndef _JCVMARRAY_HPP
#define _JCVMARRAY_HPP

#include "../jc_config.h"
#include "../types.hpp"

#ifdef JCVM_ARRAY_SIZE_CHECK
#include "../exceptions.hpp"
#endif /* JCVM_ARRAY_SIZE_CHECK */

namespace jcvm {

template <typename T> class JCVMArray {
private:
  uint16_t length;
  bool allocated_data;
  T *array;

public:
  /*
   * Default class constructor.
   */
  JCVMArray(const uint16_t length) noexcept {
    this->length = length;

    if (this->length > 0) {
      this->array = new T[length]{};
      this->allocated_data = true;
    } else {
      this->allocated_data = false;
    }
  }

  JCVMArray(const uint16_t length, T *data) noexcept {
    this->length = length;
    this->array = data;
    this->allocated_data = false;
  }

  /*
   * Default class destructor.
   */
  ~JCVMArray() noexcept {
    if (this->allocated_data) {
      delete[] this->array;
    }
  }

  /*
   * Access specified element with bounds checking.
   *
   * @param[index] Get the indexed element.
   * @return Get the indexed element.
   */
  T &operator[](uint16_t index)
#ifndef JCVM_ARRAY_SIZE_CHECK
      noexcept
#endif /* JCVM_ARRAY_SIZE_CHECK */
  {
    return this->at(index);
  }

  /*
   * Access specified element with bounds checking.
   *
   * @param[index] Get the indexed element.
   * @return Get the indexed element.
   */
  constexpr T &operator[](uint16_t index) const
#ifndef JCVM_ARRAY_SIZE_CHECK
      noexcept
#endif /* JCVM_ARRAY_SIZE_CHECK */
  {
    return this->at(index);
  }

  /*
   * Access specified element with bounds checking.
   *
   * @param[index] Get the indexed element.
   * @return Get the indexed element.
   */
  T &at(uint16_t index)
#ifndef JCVM_ARRAY_SIZE_CHECK
      noexcept
#endif /* JCVM_ARRAY_SIZE_CHECK */
  {
#ifdef JCVM_ARRAY_SIZE_CHECK

    if (index >= this->length) {
      throw Exceptions::IndexOutOfBoundsException;
    }

#endif /* JCVM_ARRAY_SIZE_CHECK */
    return this->array[index];
  }

  /*
   * Access specified element with bounds checking.
   *
   * @param[index] Get the indexed element.
   * @return Get the indexed element.
   */
  constexpr T &at(uint16_t index) const
#ifndef JCVM_ARRAY_SIZE_CHECK
      noexcept
#endif /* JCVM_ARRAY_SIZE_CHECK */
  {
#ifdef JCVM_ARRAY_SIZE_CHECK

    if (index >= this->length) {
      throw Exceptions::IndexOutOfBoundsException;
    }

#endif /* JCVM_ARRAY_SIZE_CHECK */
    return this->array[index];
  }

  /*
   * Direct access to the underlying array.
   *
   * @return Pointer to the underlying array.
   */
  T *data() noexcept { return this->array; }

  /*
   * Direct access to the underlying array.
   *
   * @return Constant pointer to the underlying array.
   */
  const T *data() const noexcept { return this->array; }

  /*
   * Returns the maximum possible number of elements
   *
   * @return the maximum possible number of elements
   */
  const uint16_t size() const noexcept { return this->length; }

  /*
   * Assigns the given value value to all elements in the container.
   *
   * @param[value] the value used to fill the array.
   */
  void fill(const T &value) noexcept {
    T *word = this->array;

    for (int index = 0; index < this->size(); ++index) {
      *word = value;
    }
  }
};

} // namespace jcvm

#endif /* _JCVMARRAY_HPP */
