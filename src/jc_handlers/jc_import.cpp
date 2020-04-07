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

#include "jc_import.hpp"
#include "../debug.hpp"
#include "../jc_cap/jc_cap_import.hpp"
#include "flashmemory.hpp"

namespace jcvm {

/*
 * Get import package AID from index.
 *
 * @param[index] package index
 * @return the AID of the package.
 */
const jc_cap_package_info *Import_Handler::getPackageAID(const uint8_t index)
#if !defined(JCVM_ARRAY_SIZE_CHECK)
    noexcept
#endif
{
  const JC_Cap &cap = this->package.getCap();
  const jc_cap_import_component *import = cap.getImport();

#ifdef JCVM_ARRAY_SIZE_CHECK

  if (import->count <= index) {

    TRACE_JCVM_DEBUG(
        "Imported package index (%u) > imported packages number (%u)", index,
        import->count);

    throw Exceptions::SecurityException;
  }

#endif /* JCVM_ARRAY_SIZE_CHECK */

  uint16_t pos = 0;
  const jc_cap_package_info *package_info;

  for (uint8_t foo = 0; foo <= index; foo++) {
    package_info = reinterpret_cast<const jc_cap_package_info *>(
        &import->imported_packages[pos]);
    pos += package_info->size();
  }

  return package_info;
}

/*
 * Get the package index in the flash.
 *
 * @param[pinfo] package info which contains the package information to find.
 */
const jpackage_ID_t
Import_Handler::getPackageIndex(const jc_cap_package_info *pinfo) {
  for (jpackage_ID_t index = 0; index < JCVM_MAX_PACKAGES; index++) {
    if (!FlashMemory_Handler::isPackageExist(index)) {
      continue;
    }

    Package package = Package(index);
    JC_Cap cap = package.getCap();

    const jc_cap_package_info &pinfo_to_compare = cap.getHeader()->package;

    if (*pinfo == pinfo_to_compare) {
      return index;
    }
  }

  throw Exceptions::RuntimeException;
}

/*
 * Get the package index in the flash from import component offset.
 *
 * @param[offset] Offset of the package information in the current import
 * component
 */
const jpackage_ID_t
Import_Handler::getPackageIndexFromOffset(const uint8_t offset) {
  auto aid = this->getPackageAID(offset);
  return this->getPackageIndex(aid);
}

} // namespace jcvm
