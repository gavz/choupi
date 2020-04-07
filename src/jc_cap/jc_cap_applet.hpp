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

#ifndef _JC_CAP_APPLET_HPP
#define _JC_CAP_APPLET_HPP

#include "../jc_utils.hpp"
#include "../jcvm_types/jcvmarray.hpp"
#include "../types.hpp"

namespace jcvm {

struct __attribute__((__packed__)) jc_cap_app {
  uint8_t AID_length; /* Applet AID length = [5,16] */
  // {
  //   uint8_t AID [/* AID_length */]; /* Applet AID */
  //   uint16_t install_method_offset; /* Applet install method offset in the
  //   Method
  //                                 component */
  // }
  uint8_t data[];

  const JCVMArray<const uint8_t> AID() const noexcept {
    return JCVMArray<const uint8_t>(NTOHS(AID_length), data);
  }

  uint16_t install_method_offset() const noexcept {
    return BYTES_TO_SHORT(this->data[AID_length], this->data[AID_length + 1]);
  }
};

struct __attribute__((__packed__)) jc_cap_applet_component {
  uint8_t tag;   /* Component tag: COMPONENT_Applet (3) */
  uint16_t size; /* Component size */
  uint8_t count; /* Number of applet defined in this package */
  jc_cap_app applets[/* count */]; /* Applet defined in this package */

  const JCVMArray<const jc_cap_app> applet() const noexcept {
    return JCVMArray<const jc_cap_app>(NTOHS(count), applets);
  }
};

} // namespace jcvm

#endif /* _JC_CAP_APPLET_HPP */
