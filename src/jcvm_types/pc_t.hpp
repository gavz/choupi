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

#ifndef _PC_T_HPP
#define _PC_T_HPP

#include "../jc_config.h"
#include "../jc_utils.hpp"
#include "../types.hpp"

namespace jcvm {
class pc_t {
private:
  const uint8_t *value;
  /**
   * Incrementing PC value
   */
  void inc() noexcept { this->value += 1; }

public:
  /**
   * Defaut constructor
   *
   * @param[value] initial PC value
   */
  pc_t(const uint8_t *value) { this->value = value; }

  /**
   * Sets the new PC value
   *
   * @param[value] new PC value
   */
  void setValue(pc_t pc) { this->value = pc.value; }

  /**
   * Sets the new PC value
   *
   * @param[value] new PC value
   */
  void setValue(const uint8_t *value) { this->value = value; }

  /**
   * Returns the PC value.
   */
  const uint8_t *getValue() const noexcept { return this->value; }

  /**
   * Gets next byte value and increment the PC value.
   */
  jbyte_t getNextByte() noexcept {
    jbyte_t ret = (jbyte_t) * (this->value);
    this->inc();
    return ret;
  }

  /**
   * Gets next 2-byte value and increment the PC value.
   */
  jshort_t getNextShort() noexcept {
    jbyte_t msb = (jbyte_t) * (this->value);
    this->inc();
    jbyte_t lsb = (jbyte_t) * (this->value);
    this->inc();
    return BYTES_TO_SHORT(msb, lsb);
  }

#ifdef JCVM_INT_SUPPORTED
  /**
   * Gets next 4-byte value and increment the PC value.
   */
  jint_t getNextInt() noexcept {
    jbyte_t msb0 = (jbyte_t) * (this->value);
    this->inc();
    jbyte_t lsb0 = (jbyte_t) * (this->value);
    this->inc();
    jbyte_t msb1 = (jbyte_t) * (this->value);
    this->inc();
    jbyte_t lsb1 = (jbyte_t) * (this->value);
    this->inc();
    return BYTES_TO_INT(msb0, lsb0, msb1, lsb1);
  }
#endif /* JCVM_INT_SUPPORTED */

  /**
   * Update the PC value from an relative offset
   *
   * @param [offset] relative offset used to update the PC value
   */
  void updateFromOffset(const jshort_t offset) { this->value += offset; }
};

} // namespace jcvm

#endif /* _PC_T_HPP */
