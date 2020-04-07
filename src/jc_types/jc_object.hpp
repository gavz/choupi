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

#ifndef _JC_OBJECT_HPP
#define _JC_OBJECT_HPP

#include "../jc_config.h"
#include "../types.hpp"

namespace jcvm {

class Heap; // fast forward declation;

class JC_Object {
private:
  /// Heap owner
  Heap &owner;
  /// Is a persistent (aka in flash memory) object?
  bool is_persistent;
  /// Is a static (aka in flash memory) object?
  bool is_static;

public:
  /// Default constructor
  JC_Object(Heap &owner, const bool isPersistent) noexcept
      : owner(owner), is_persistent(isPersistent){};

  /// Gets the persistant state of the current object
  bool isPersistent(void) const noexcept;
  /// Sets the persistant state of the current object
  void setPersistent(const bool persistant) noexcept;

  /// Get heap owner.
  Heap &getOwner() noexcept;
};

} // namespace jcvm
#endif /* _JC_OBJECT_HPP */
