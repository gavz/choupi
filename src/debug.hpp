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

#ifndef __DEBUG_HPP_
#define __DEBUG_HPP_

#ifdef DEBUG
#include <stdio.h>
#endif /* DEBUG */

#ifdef __cplusplus
extern "C" {
#endif

//        Trace function
#ifdef DEBUG
#define TRACE_JCVM_DEBUG(fmt, ...) printf("[-] " fmt "\r\n", ##__VA_ARGS__)
#define TRACE_JCVM_ERR(fmt, ...) printf("[!] " fmt "\r\n", ##__VA_ARGS__)
#else
#define TRACE_JCVM_DEBUG(fmt, ...) ;
#define TRACE_JCVM_ERR(fmt, ...) ;
#endif /* DEBUG */

#ifdef __cplusplus
}
#endif

#ifdef DEBUG
#pragma message "CHOUPI Debug mode enable"
#endif /* DEBUG */

#endif /* __DEBUG_HPP_ */
