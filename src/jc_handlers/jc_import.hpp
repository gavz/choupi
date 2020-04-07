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

#ifndef _JC_IMPORT_HPP
#define _JC_IMPORT_HPP

#include "../jc_config.h"

#include "../jc_cap/jc_cap_header.hpp"
#include "../jcvm_types/jcvmarray.hpp"
#include "../types.hpp"
#include "jc_component.hpp"

namespace jcvm {

class Import_Handler : public Component_Handler {
public:
  /// Default constructor
  Import_Handler(Package package) noexcept : Component_Handler(package){};

  /// Get import package AID from index.
  const jc_cap_package_info *getPackageAID(const uint8_t index)
#if !defined(JCVM_ARRAY_SIZE_CHECK)
      noexcept
#endif
      ;

  /// Get the package index in the flash.
  const jpackage_ID_t getPackageIndex(const jc_cap_package_info *pinfo);

  /// Get the package index in the flash from import component offset.
  const jpackage_ID_t getPackageIndexFromOffset(const uint8_t offset);
};

} // namespace jcvm

#endif /* _JC_IMPORT_HPP */
