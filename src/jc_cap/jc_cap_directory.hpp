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

#ifndef _JC_CAP_DIRECTORY_HPP
#define _JC_CAP_DIRECTORY_HPP

#include "../jc_utils.hpp"
#include "../jcvm_types/jcvmarray.hpp"
#include "../types.hpp"

namespace jcvm {

struct __attribute__((__packed__)) jc_cap_static_field_size_info {
  uint16_t image_size;       /* Total number of bytes in the static fields */
  uint16_t array_init_count; /* Number of arrays initialized */
  uint16_t
      array_init_size; /* Number of bytes in all of the arrays initialized */
};

struct __attribute__((__packed__)) jc_cap_custom_component_info {
  uint8_t component_tag; /* Custom component tag = [128, 255] */
  uint16_t size;         /* Custom component size */
  uint8_t AID_length;    /* Package AID length = [5,16] */
  uint8_t AID[/* AID_length */];

  const JCVMArray<const uint8_t> aid() const noexcept {
    return JCVMArray<const uint8_t>(AID_length, AID);
  }
};

struct __attribute__((__packed__)) jc_cap_directory_component {
  uint8_t tag;                  /* Component size: COMPONENT_Directory (2) */
  uint16_t size;                /* Component size */
  uint16_t component_sizes[11]; /* Size of CAP file components */
  jc_cap_static_field_size_info static_field_size; /* Static field size */
  uint8_t import_count; /* Number of packages imported */
  uint8_t applet_count; /* Number of applet defined in this package */
  uint8_t custom_count; /* Number of entries in the custom_components table */
  jc_cap_custom_component_info custom_components[/* custom_count */];

  const JCVMArray<const jc_cap_custom_component_info> customcomponents() const
      noexcept {
    return JCVMArray<const jc_cap_custom_component_info>(custom_count,
                                                         custom_components);
  }
};

} // namespace jcvm

#endif /* _JC_CAP_DIRECTORY_HPP */
