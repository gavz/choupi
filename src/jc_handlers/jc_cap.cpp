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

#include "jc_cap.hpp"
#include "../exceptions.hpp"
#include <utility>

namespace jcvm {

/// CAP File component tag values
#define CAP_COMPONENT_HEADER (uint8_t)1
#define CAP_COMPONENT_DIRECTORY (uint8_t)2
#define CAP_COMPONENT_APPLET (uint8_t)3
#define CAP_COMPONENT_IMPORT (uint8_t)4
#define CAP_COMPONENT_CONSTANT_POOL (uint8_t)5
#define CAP_COMPONENT_CLASS (uint8_t)6
#define CAP_COMPONENT_METHOD (uint8_t)7
#define CAP_COMPONENT_STATIC_FIELD (uint8_t)8
#define CAP_COMPONENT_REFERENCE_LOCATION (uint8_t)9
#define CAP_COMPONENT_EXPORT (uint8_t)10
#define CAP_COMPONENT_DESCRIPTOR (uint8_t)11

/**
 * Default constructor
 *
 * @param[length] CAP file length
 * @param[cap_file] A pointer to the CAP file data
 */
JC_Cap::JC_Cap(uint16_t length, const uint8_t *cap_file) {
  const uint8_t *component = cap_file;
  const uint8_t *cap_file_end = cap_file + length;

  while (component < cap_file_end) {

    uint8_t component_tag = *component;

    switch (component_tag) {
    case CAP_COMPONENT_HEADER:
      if (this->header_comp != nullptr) {
        throw Exceptions::SecurityException;
      }

      this->header_comp =
          reinterpret_cast<const jc_cap_header_component *>(component);
      component += sizeof(this->header_comp->tag) +
                   sizeof(this->header_comp->size) +
                   HTONS(this->header_comp->size);

      break;

    case CAP_COMPONENT_DIRECTORY:
      if (this->directory_comp != nullptr) {
        throw Exceptions::SecurityException;
      }

      this->directory_comp =
          reinterpret_cast<const jc_cap_directory_component *>(component);
      component += sizeof(this->directory_comp->tag) +
                   sizeof(this->directory_comp->size) +
                   HTONS(this->directory_comp->size);
      break;

    case CAP_COMPONENT_APPLET:
      if (this->applet_comp != nullptr) {
        throw Exceptions::SecurityException;
      }

      this->applet_comp =
          reinterpret_cast<const jc_cap_applet_component *>(component);
      component += sizeof(this->applet_comp->tag) +
                   sizeof(this->applet_comp->size) +
                   HTONS(this->applet_comp->size);
      break;

    case CAP_COMPONENT_IMPORT:
      if (this->import_comp != nullptr) {
        throw Exceptions::SecurityException;
      }

      this->import_comp =
          reinterpret_cast<const jc_cap_import_component *>(component);
      component += sizeof(this->import_comp->tag) +
                   sizeof(this->import_comp->size) +
                   HTONS(this->import_comp->size);
      break;

    case CAP_COMPONENT_CONSTANT_POOL:
      if (this->constantPool_comp != nullptr) {
        throw Exceptions::SecurityException;
      }

      this->constantPool_comp =
          reinterpret_cast<const jc_cap_constant_pool_component *>(component);
      component += sizeof(this->constantPool_comp->tag) +
                   sizeof(this->constantPool_comp->size) +
                   HTONS(this->constantPool_comp->size);
      break;

    case CAP_COMPONENT_CLASS:
      if (this->class_comp != nullptr) {
        throw Exceptions::SecurityException;
      }

      this->class_comp =
          reinterpret_cast<const jc_cap_class_component *>(component);
      component += sizeof(this->class_comp->tag) +
                   sizeof(this->class_comp->size) +
                   HTONS(this->class_comp->size);
      break;

    case CAP_COMPONENT_METHOD:
      if (this->method_comp != nullptr) {
        throw Exceptions::SecurityException;
      }

      this->method_comp =
          reinterpret_cast<const jc_cap_method_component *>(component);
      component += sizeof(this->method_comp->tag) +
                   sizeof(this->method_comp->size) +
                   HTONS(this->method_comp->size);
      break;

    case CAP_COMPONENT_STATIC_FIELD:
      if (this->staticField_comp != nullptr) {
        throw Exceptions::SecurityException;
      }

      this->staticField_comp =
          reinterpret_cast<const jc_cap_static_field_component *>(component);
      component += sizeof(this->staticField_comp->tag) +
                   sizeof(this->staticField_comp->size) +
                   HTONS(this->staticField_comp->size);
      break;

    case CAP_COMPONENT_REFERENCE_LOCATION:
      if (this->referenceLocation_comp != nullptr) {
        throw Exceptions::SecurityException;
      }

      this->referenceLocation_comp =
          reinterpret_cast<const jc_cap_reference_location_component *>(
              component);
      component += sizeof(this->referenceLocation_comp->tag) +
                   sizeof(this->referenceLocation_comp->size) +
                   HTONS(this->referenceLocation_comp->size);
      break;

    case CAP_COMPONENT_EXPORT:
      if (this->export_comp != nullptr) {
        throw Exceptions::SecurityException;
      }

      this->export_comp =
          reinterpret_cast<const jc_cap_export_component *>(component);
      component += sizeof(this->export_comp->tag) +
                   sizeof(this->export_comp->size) +
                   HTONS(this->export_comp->size);
      break;

    case CAP_COMPONENT_DESCRIPTOR:
      if (this->descriptor_comp != nullptr) {
        throw Exceptions::SecurityException;
      }

      this->descriptor_comp =
          reinterpret_cast<const jc_cap_descriptor_component *>(component);
      component += sizeof(this->descriptor_comp->tag) +
                   sizeof(this->descriptor_comp->size) +
                   HTONS(this->descriptor_comp->size);
      break;

    default: // byte unknown value
      throw Exceptions::SecurityException;
    }
  }

  return;
}

/**
 * Copy assignment operator
 */
JC_Cap &JC_Cap::operator=(const JC_Cap &cap) noexcept {
  this->header_comp = cap.header_comp;
  this->directory_comp = cap.directory_comp;
  this->import_comp = cap.import_comp;
  this->applet_comp = cap.applet_comp;
  this->class_comp = cap.class_comp;
  this->method_comp = cap.method_comp;
  this->staticField_comp = cap.staticField_comp;
  this->export_comp = cap.export_comp;
  this->constantPool_comp = cap.constantPool_comp;
  this->referenceLocation_comp = cap.referenceLocation_comp;
  this->descriptor_comp = cap.descriptor_comp;

  return *this;
}

/**
 * Move assignment operator
 */
JC_Cap &JC_Cap::operator=(const JC_Cap &&cap) noexcept {
  this->header_comp = std::move(cap.header_comp);
  this->directory_comp = std::move(cap.directory_comp);
  this->import_comp = std::move(cap.import_comp);
  this->applet_comp = std::move(cap.applet_comp);
  this->class_comp = std::move(cap.class_comp);
  this->method_comp = std::move(cap.method_comp);
  this->staticField_comp = std::move(cap.staticField_comp);
  this->export_comp = std::move(cap.export_comp);
  this->constantPool_comp = std::move(cap.constantPool_comp);
  this->referenceLocation_comp = std::move(cap.referenceLocation_comp);
  this->descriptor_comp = std::move(cap.descriptor_comp);
  return *this;
}

/**
 * Equality operator
 */
bool JC_Cap::operator==(JC_Cap &cap) const noexcept {
  return (this->getHeader()->package == cap.getHeader()->package);
}

/**
 * Get Header component
 *
 * @return Header component
 */
const jc_cap_header_component *JC_Cap::getHeader() const noexcept {
  return this->header_comp;
}

/**
 * Get Directory component
 *
 * @return Directory component
 */
const jc_cap_directory_component *JC_Cap::getDirectory() const noexcept {
  return this->directory_comp;
}

/**
 * Get Import component
 *
 * @return Import component
 */
const jc_cap_import_component *JC_Cap::getImport() const noexcept {
  return this->import_comp;
}

/**
 * Get Applet component
 *
 * @return Applet component
 */
const jc_cap_applet_component *JC_Cap::getApplet() const noexcept {
  return this->applet_comp;
}

/**
 * Get Class component
 *
 * @return Class component
 */
const jc_cap_class_component *JC_Cap::getClass() const noexcept {
  return this->class_comp;
}

/**
 * Get Method component
 *
 * @return Method component
 */
const jc_cap_method_component *JC_Cap::getMethod() const noexcept {
  return this->method_comp;
}

/**
 * Get StaticField component
 *
 * @return StaticField component
 */
const jc_cap_static_field_component *JC_Cap::getStaticField() const noexcept {
  return this->staticField_comp;
}

/**
 * Get Export component
 *
 * @return Export component
 */
const jc_cap_export_component *JC_Cap::getExport() const noexcept {
  return this->export_comp;
}

/**
 * Get ConstantPool component
 *
 * @return ConstantPool component
 */
const jc_cap_constant_pool_component *JC_Cap::getConstantPool() const noexcept {
  return this->constantPool_comp;
}

/**
 * Get ReferenceLocation component
 *
 * @return ReferenceLocation component
 */
const jc_cap_reference_location_component *JC_Cap::getReferenceLocation() const
    noexcept {
  return this->referenceLocation_comp;
}

/**
 * Get Descriptor component
 *
 * @return Descriptor component
 */
const jc_cap_descriptor_component *JC_Cap::getDescriptor() const noexcept {
  return this->descriptor_comp;
}

} // namespace jcvm
