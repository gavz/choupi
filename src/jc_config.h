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

#ifndef _JCVM_CONFIG_H
#define _JCVM_CONFIG_H

#define JCVM_STACK_SIZE (uint16_t)(1024 >> 2) // 2-Bytes
#define JCVM_MAX_HEAP_SIZE (uint16_t)256      // bytes
/// NOTE: This size must be < to 0x7FFE. A max size more than 0x7FFE will occur
/// several bugs.
#define JCVM_MAX_APPLETS (uint16_t)40 // applets (max 255)
#define JCVM_MAX_PACKAGES (uint8_t)64 // packages (max 255)

#define JCRE_CLEAN_STACK
#define JCVM_INT_SUPPORTED
#define JCRE_STACK_OVERFLOW_PROTECTION
#define JCVM_SECURE_HEAP_ACCESS
#define JCVM_DYNAMIC_CHECKS_CAP
#define JCVM_FIREWALL_CHECKS
#define JCVM_ARRAY_SIZE_CHECK

#define NVM_LITTLE_ENDIAN

#undef JCRE_SWITCH_PROTECTION // TODO: To be tested and implemented
#undef JCVM_TYPED_HEAP        // TODO: not yet implemented
#undef JCVM_TYPED_STACK       // TODO: not yet implemented

#endif /* _JCVM_CONFIG_H */
