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

#include "jref_t.hpp"
#include "../jc_handlers/flashmemory.hpp"

namespace jcvm {

/**
 * Default constructor.
 *
 * @param[value] Value to initialise the jref_t object.
 */
jref_t::jref_t(uint16_t value) noexcept : value(value){};

/**
 * Copy constructor.
 *
 * @param[in] jref_t object to copy;
 * @return copied object.
 */
jref_t &jref_t::operator=(const jref_t &in) {
  this->value.packed = in.value.packed;
  return *this;
}

/**
 * Get a compact version of this class.
 *
 * @return the compact version of this class.
 */
uint16_t jref_t::compact() const noexcept { return this->value.packed; }

/*
 * Is an array?
 *
 * @return true if jref is an array
 */
bool jref_t::isArray() const noexcept { return this->value.unpacked.isArray; }

/*
 * Set as an array
 *
 * @return true if jref is an array
 */
void jref_t::setAsArray(const bool isArray) noexcept {
  this->value.unpacked.isArray = isArray;
}

/*
 * Is an instance?
 *
 * @return true if jref is an instance
 */
bool jref_t::isInstance() const noexcept {
  return !this->value.unpacked.isArray;
}

/*
 * Set as an instance
 *
 * @return true if jref is an instance
 */
void jref_t::setAsInstance(const bool isInstance) noexcept {
  this->value.unpacked.isArray = !isInstance;
}

/**
 * Get reference object.
 *
 * @return the reference object.
 */
uint16_t jref_t::getOffset() const noexcept {
  return this->value.unpacked.offset;
}

/**
 * Set reference object.
 *
 * @param[offset] new offset flag.
 */
void jref_t::setOffset(const uint16_t offset) noexcept {
  this->value.unpacked.offset = offset;
}

/**
 * Is a Java Null pointer.
 *
 * @return True if it is a Java Card Null pointer.
 */
bool jref_t::isNullPointer() const noexcept {
  return (this->value.unpacked.offset == 0);
}

/**
 * Equality operator.
 *
 * @param[ref] the ref to compare.
 * @return the equality comparison.
 */
bool jref_t::operator==(const jref_t &ref) const noexcept {
  return (this->value.packed == ref.value.packed);
}

/**
 * Inequality operator.
 *
 * @param[ref] the ref to compare.
 * @return the inequality comparison.
 */
bool jref_t::operator!=(const jref_t &ref) const noexcept {
  return (this->value.packed != ref.value.packed);
}

/**
 * Less than operator.
 *
 * @param[ref] the ref to compare.
 * @return the less than comparison.
 */
bool jref_t::operator<(const jref_t &ref) const noexcept {
  return (this->value.packed < ref.value.packed);
}

/**
 * Less than or equality operator.
 *
 * @param[ref] the ref to compare.
 * @return the less than or equal comparison.
 */
bool jref_t::operator<=(const jref_t &ref) const noexcept {
  return (this->value.packed <= ref.value.packed);
}

/**
 * Greater than operator.
 *
 * @param[ref] the ref to compare.
 * @return the greater than comparison.
 */
bool jref_t::operator>(const jref_t &ref) const noexcept {
  return (this->value.packed > ref.value.packed);
}

/**
 * Greater than or equality operator.
 *
 * @param[ref] the ref to compare.
 * @return the greater than or equal comparison.
 */
bool jref_t::operator>=(const jref_t &ref) const noexcept {
  return (this->value.packed >= ref.value.packed);
}

} // namespace jcvm
