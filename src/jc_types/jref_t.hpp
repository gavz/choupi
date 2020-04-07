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

#ifndef _JREF_T_HPP
#define _JREF_T_HPP

#include "../exceptions.hpp"
#include "../types.hpp"

namespace jcvm {

/// a Java Card reference
struct jref_t {
private:
  union _jref_t_type {
    struct {
      uint16_t isArray : 1;
      uint16_t offset : 15;
    } unpacked;
    uint16_t packed;

    _jref_t_type(const uint16_t value) noexcept { this->packed = value; };

  } value;

public:
  /// Default constructor.
  jref_t(uint16_t value = 0) noexcept;
  /// Move constructor.
  jref_t(const jref_t &) = default;
  /// Copy constructor.
  jref_t &operator=(const jref_t &);

  /// Get a compact version of this class.
  uint16_t compact() const noexcept;

  /// Is an array?
  bool isArray() const noexcept;
  /// Set as an array
  void setAsArray(const bool isArray) noexcept;
  // Is an instance?
  bool isInstance() const noexcept;
  /// Set as an instance
  void setAsInstance(const bool isInstance) noexcept;

  /// Get reference object in case of non persistent data.
  uint16_t getOffset() const noexcept;
  /// Set reference object.
  void setOffset(const uint16_t offset) noexcept;

  /// Is a Java NULL pointer.
  bool isNullPointer() const noexcept;

  /// Equality operator.
  bool operator==(const jref_t &) const noexcept;
  /// Inequality operator.
  bool operator!=(const jref_t &) const noexcept;
  /// Less than operator.
  bool operator<(const jref_t &) const noexcept;
  /// Less than or equality operator.
  bool operator<=(const jref_t &) const noexcept;
  /// Greater than operator.
  bool operator>(const jref_t &) const noexcept;
  /// Greater than or equality operator.
  bool operator>=(const jref_t &) const noexcept;

}; // reference type

} // namespace jcvm

#endif /* _JREF_T_HPP */
