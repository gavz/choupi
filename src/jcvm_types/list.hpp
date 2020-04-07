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

#ifndef _LIST_HPP
#define _LIST_HPP

#include "../jc_config.h"
#include "../types.hpp"
#include <algorithm>
#include <list>

#ifdef JCVM_ARRAY_SIZE_CHECK
#include "../exceptions.hpp"
#endif /* JCVM_ARRAY_SIZE_CHECK */

namespace jcvm {
template <class T> class List : public std::list<T> {

public:
  /// Access specified element with bounds checking.
  constexpr T &at(uint16_t index)
#ifndef JCVM_ARRAY_SIZE_CHECK
      noexcept
#endif /* JCVM_ARRAY_SIZE_CHECK */
  {
    typename std::list<T>::iterator lit = this->begin();

#ifdef JCVM_ARRAY_SIZE_CHECK

    if (index >= this->size()) {
      throw Exceptions::IndexOutOfBoundsException;
    }

#endif /* JCVM_ARRAY_SIZE_CHECK */

    // list iterator is a bidirectional iterator without random access.
    for (uint16_t foo = 0; foo < index; ++foo) {
      lit++;
    }

    return *lit;
  }

  constexpr T &at(uint16_t index) const
#ifndef JCVM_ARRAY_SIZE_CHECK
      noexcept
#endif /* JCVM_ARRAY_SIZE_CHECK */
  {
    typename std::list<T>::const_iterator lit = this->cbegin();

#ifdef JCVM_ARRAY_SIZE_CHECK

    if (index >= this->size()) {
      throw Exceptions::IndexOutOfBoundsException;
    }

#endif /* JCVM_ARRAY_SIZE_CHECK */

    // list iterator is a bidirectional iterator without random access.
    for (uint16_t foo = 0; foo < index; ++foo) {
      lit++;
    }

    return *lit;
  }
};

} // namespace jcvm

#endif /* _LIST_HPP */
