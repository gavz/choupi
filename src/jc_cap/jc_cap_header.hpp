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

#ifndef _JC_CAP_HEADER_HPP
#define _JC_CAP_HEADER_HPP

#include "../jc_utils.hpp"
#include "../jcvm_types/jcvmarray.hpp"
#include "../types.hpp"
#include <cstring>

namespace jcvm {

struct __attribute__((__packed__)) jc_cap_package_info {
  uint8_t minor_version;         /* Package minor version */
  uint8_t major_version;         /* Package major version */
  uint8_t AID_length;            /* Package AID Length */
  uint8_t AID[/* AID_length */]; /* Package AID */

  const JCVMArray<const uint8_t> aid() const noexcept {
    return JCVMArray<const uint8_t>(AID_length, AID);
  }

  jbool_t operator==(const jc_cap_package_info &package_info) const noexcept {
    if (AID_length != package_info.AID_length) {
      return FALSE;
    }

    if ((major_version != package_info.major_version) ||
        (minor_version != package_info.minor_version)) {
      return FALSE;
    }

    if (memcmp(AID, package_info.AID, AID_length) == 0) {
      return TRUE;
    }

    return FALSE;
  }

  const uint32_t size() const noexcept {
    return sizeof(jc_cap_package_info) +
           this->AID_length * sizeof(this->AID[0]);
  }
};

struct __attribute__((__packed__)) jc_cap_header_component {
  uint8_t tag;                 /* Component tag: COMPONENT_Header (1) */
  uint16_t size;               /* Component size */
  uint32_t magic;              /* CAP file magic number = 0xDECAFFED */
  uint8_t minor_version;       /* CAP File version */
  uint8_t major_version;       /* XXX: only the version 2.1 is implemented */
  uint8_t flags;               /* CAP File features used */
  jc_cap_package_info package; /* Implemented package info */
};

#define JC_CAP_FLAG_ACC_INT 0x01
#define JC_CAP_FLAG_ACC_EXPORT 0x02
#define JC_CAP_FLAG_ACC_APPLET 0x04

} // namespace jcvm

#endif /* _JC_CAP_HEADER_HPP */
