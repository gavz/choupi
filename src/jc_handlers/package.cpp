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

#include "package.hpp"
#include "../jc_utils.hpp"
#include "../jcvm_types/jcvmarray.hpp"
#include "flashmemory.hpp"

namespace jcvm {

/**
 * Default constructor.
 *
 * @param[packageID] package ID
 */
Package::Package(const jpackage_ID_t packageID) noexcept : ID(packageID) {}

/**
 * Equality operator
 *
 * @param[package]
 *
 * @return True if packages are not equal.
 */
bool Package::operator==(const Package &package) const {
  return (this->ID == package.ID);
}

/**
 * Inequality operator
 *
 * @param[package]
 *
 * @return True if packages are equal.
 */
bool Package::operator!=(const Package &package) const {
  return (this->ID != package.ID);
}

/**
 * Get Package ID
 */
jpackage_ID_t Package::getPackageID() const noexcept { return this->ID; }

/**
 * Get CAP File
 *
 * @return Package CAP file.
 */
JC_Cap Package::getCap() const { return FlashMemory_Handler::getCap(this->ID); }

} // namespace jcvm
