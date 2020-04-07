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

#ifndef _BYTECODE_VALUES_HPP
#define _BYTECODE_VALUES_HPP

namespace jcvm {

enum bytecode_type {
  /* 0x00 */ BC_NOP,
  /* 0x01 */ BC_ACONST_NULL,
  /* 0x02 */ BC_SCONST_M1,
  /* 0x03 */ BC_SCONST_0,
  /* 0x04 */ BC_SCONST_1,
  /* 0x05 */ BC_SCONST_2,
  /* 0x06 */ BC_SCONST_3,
  /* 0x07 */ BC_SCONST_4,
  /* 0x08 */ BC_SCONST_5,
#ifdef JCVM_INT_SUPPORTED
  /* 0x09 */ BC_ICONST_M1,
  /* 0x0A */ BC_ICONST_0,
  /* 0x0B */ BC_ICONST_1,
  /* 0x0C */ BC_ICONST_2,
  /* 0x0D */ BC_ICONST_3,
  /* 0x0E */ BC_ICONST_4,
  /* 0x0F */ BC_ICONST_5,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x10 */ BC_BSPUSH,
  /* 0x11 */ BC_SSPUSH,
#ifdef JCVM_INT_SUPPORTED
  /* 0x12 */ BC_BIPUSH,
  /* 0x13 */ BC_SIPUSH,
  /* 0x14 */ BC_IIPUSH,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x15 */ BC_ALOAD,
  /* 0x16 */ BC_SLOAD,
#ifdef JCVM_INT_SUPPORTED
  /* 0x17 */ BC_ILOAD,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x18 */ BC_ALOAD_0,
  /* 0x19 */ BC_ALOAD_1,
  /* 0x1A */ BC_ALOAD_2,
  /* 0x1B */ BC_ALOAD_3,
  /* 0x1C */ BC_SLOAD_0,
  /* 0x1D */ BC_SLOAD_1,
  /* 0x1E */ BC_SLOAD_2,
  /* 0x1F */ BC_SLOAD_3,
#ifdef JCVM_INT_SUPPORTED
  /* 0x20 */ BC_ILOAD_0,
  /* 0x21 */ BC_ILOAD_1,
  /* 0x22 */ BC_ILOAD_2,
  /* 0x23 */ BC_ILOAD_3,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x24 */ BC_AALOAD,
  /* 0x25 */ BC_BALOAD,
  /* 0x26 */ BC_SALOAD,
#ifdef JCVM_INT_SUPPORTED
  /* 0x27 */ BC_IALOAD,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x28 */ BC_ASTORE,
  /* 0x29 */ BC_SSTORE,
  /* 0x2A */ BC_ISTORE,
  /* 0x2B */ BC_ASTORE_0,
  /* 0x2C */ BC_ASTORE_1,
  /* 0x2D */ BC_ASTORE_2,
  /* 0x2E */ BC_ASTORE_3,
  /* 0x2F */ BC_SSTORE_0,
  /* 0x30 */ BC_SSTORE_1,
  /* 0x31 */ BC_SSTORE_2,
  /* 0x32 */ BC_SSTORE_3,
#ifdef JCVM_INT_SUPPORTED
  /* 0x33 */ BC_ISTORE_0,
  /* 0x34 */ BC_ISTORE_1,
  /* 0x35 */ BC_ISTORE_2,
  /* 0x36 */ BC_ISTORE_3,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x37 */ BC_AASTORE,
  /* 0x38 */ BC_BASTORE,
  /* 0x39 */ BC_SASTORE,
#ifdef JCVM_INT_SUPPORTED
  /* 0x3A */ BC_IASTORE,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x3B */ BC_POP,
  /* 0x3C */ BC_POP2,
  /* 0x3D */ BC_DUP,
  /* 0x3E */ BC_DUP2,
  /* 0x3F */ BC_DUP_X,
  /* 0x40 */ BC_SWAP_X,
  /* 0x41 */ BC_SADD,
#ifdef JCVM_INT_SUPPORTED
  /* 0x42 */ BC_IADD,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x43 */ BC_SSUB,
#ifdef JCVM_INT_SUPPORTED
  /* 0x44 */ BC_ISUB,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x45 */ BC_SMUL,
#ifdef JCVM_INT_SUPPORTED
  /* 0x46 */ BC_IMUL,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x47 */ BC_SDIV,
#ifdef JCVM_INT_SUPPORTED
  /* 0x48 */ BC_IDIV,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x49 */ BC_SREM,
#ifdef JCVM_INT_SUPPORTED
  /* 0x4A */ BC_IREM,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x4B */ BC_SNEG,
#ifdef JCVM_INT_SUPPORTED
  /* 0x4C */ BC_INEG,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x4D */ BC_SSHL,
#ifdef JCVM_INT_SUPPORTED
  /* 0x4E */ BC_ISHL,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x4F */ BC_SSHR,
#ifdef JCVM_INT_SUPPORTED
  /* 0x50 */ BC_ISHR,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x51 */ BC_SUSHR,
#ifdef JCVM_INT_SUPPORTED
  /* 0x52 */ BC_IUSHR,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x53 */ BC_SAND,
#ifdef JCVM_INT_SUPPORTED
  /* 0x54 */ BC_IAND,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x55 */ BC_SOR,
#ifdef JCVM_INT_SUPPORTED
  /* 0x56 */ BC_IOR,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x57 */ BC_SXOR,
#ifdef JCVM_INT_SUPPORTED
  /* 0x58 */ BC_IXOR,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x59 */ BC_SINC,
#ifdef JCVM_INT_SUPPORTED
  /* 0x5A */ BC_IINC,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x5B */ BC_S2B,
#ifdef JCVM_INT_SUPPORTED
  /* 0x5C */ BC_S2I,
  /* 0x5D */ BC_I2B,
  /* 0x5E */ BC_I2S,
  /* 0x5F */ BC_ICMP,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x60 */ BC_IFEQ,
  /* 0x61 */ BC_IFNE,
  /* 0x62 */ BC_IFLT,
  /* 0x63 */ BC_IFGE,
  /* 0x64 */ BC_IFGT,
  /* 0x65 */ BC_IFLE,
  /* 0x66 */ BC_IFNULL,
  /* 0x67 */ BC_IFNONNULL,
  /* 0x68 */ BC_IF_ACMPEQ,
  /* 0x69 */ BC_IF_ACMPNE,
  /* 0x6A */ BC_IF_SCMPEQ,
  /* 0x6B */ BC_IF_SCMPNE,
  /* 0x6C */ BC_IF_SCMPLT,
  /* 0x6D */ BC_IF_SCMPGE,
  /* 0x6E */ BC_IF_SCMPGT,
  /* 0x6F */ BC_IF_SCMPLE,
  /* 0x70 */ BC_GOTO,
  /* 0x71 */ BC_JSR,
  /* 0x72 */ BC_RET,
  /* 0x73 */ BC_STABLESWITCH,
  /* 0x74 */ BC_ITABLESWITCH,
  /* 0x75 */ BC_SLOOKUPSWITCH,
#ifdef JCVM_INT_SUPPORTED
  /* 0x76 */ BC_ILOOKUPSWITCH,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x77 */ BC_ARETURN,
  /* 0x78 */ BC_SRETURN,
#ifdef JCVM_INT_SUPPORTED
  /* 0x79 */ BC_IRETURN,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x7A */ BC_RETURN,
  /* 0x7B */ BC_GETSTATIC_A,
  /* 0x7C */ BC_GETSTATIC_B,
  /* 0x7D */ BC_GETSTATIC_S,
#ifdef JCVM_INT_SUPPORTED
  /* 0x7E */ BC_GETSTATIC_I,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x7F */ BC_PUTSTATIC_A,
  /* 0x80 */ BC_PUTSTATIC_B,
  /* 0x81 */ BC_PUTSTATIC_S,
#ifdef JCVM_INT_SUPPORTED
  /* 0x82 */ BC_PUTSTATIC_I,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x83 */ BC_GETFIELD_A,
  /* 0x84 */ BC_GETFIELD_B,
  /* 0x85 */ BC_GETFIELD_S,
#ifdef JCVM_INT_SUPPORTED
  /* 0x86 */ BC_GETFIELD_I,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x87 */ BC_PUTFIELD_A,
  /* 0x88 */ BC_PUTFIELD_B,
  /* 0x89 */ BC_PUTFIELD_S,
#ifdef JCVM_INT_SUPPORTED
  /* 0x8A */ BC_PUTFIELD_I,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x8B */ BC_INVOKEVIRTUAL,
  /* 0x8C */ BC_INVOKESPECIAL,
  /* 0x8D */ BC_INVOKESTATIC,
  /* 0x8E */ BC_INVOKEINTERFACE,
  /* 0x8F */ BC_NEW,
  /* 0x90 */ BC_NEWARRAY,
  /* 0x91 */ BC_ANEWARRAY,
  /* 0x92 */ BC_ARRAYLENGTH,
  /* 0x93 */ BC_ATHROW,
  /* 0x94 */ BC_CHECKCAST,
  /* 0x95 */ BC_INSTANCEOF,
  /* 0x96 */ BC_SINC_W,
#ifdef JCVM_INT_SUPPORTED
  /* 0x97 */ BC_IINC_W,
#endif /* JCVM_INT_SUPPORTED */
  /* 0x98 */ BC_IFEQ_W,
  /* 0x99 */ BC_IFNE_W,
  /* 0x9A */ BC_IFLT_W,
  /* 0x9B */ BC_IFGE_W,
  /* 0x9C */ BC_IFGT_W,
  /* 0x9D */ BC_IFLE_W,
  /* 0x9E */ BC_IFNULL_W,
  /* 0x9F */ BC_IFNONNULL_W,
  /* 0xA0 */ BC_IF_ACMPEQ_W,
  /* 0xA1 */ BC_IF_ACMPNE_W,
  /* 0xA2 */ BC_IF_SCMPEQ_W,
  /* 0xA3 */ BC_IF_SCMPNE_W,
  /* 0xA4 */ BC_IF_SCMPLT_W,
  /* 0xA5 */ BC_IF_SCMPGE_W,
  /* 0xA6 */ BC_IF_SCMPGT_W,
  /* 0xA7 */ BC_IF_SCMPLE_W,
  /* 0xA8 */ BC_GOTO_W,
  /* 0xA9 */ BC_GETFIELD_A_W,
  /* 0xAA */ BC_GETFIELD_B_W,
  /* 0xAB */ BC_GETFIELD_S_W,
#ifdef JCVM_INT_SUPPORTED
  /* 0xAC */ BC_GETFIELD_I_W,
#endif /* JCVM_INT_SUPPORTED */
  /* 0xAD */ BC_GETFIELD_A_THIS,
  /* 0xAE */ BC_GETFIELD_B_THIS,
  /* 0xAF */ BC_GETFIELD_S_THIS,
#ifdef JCVM_INT_SUPPORTED
  /* 0xB0 */ BC_GETFIELD_I_THIS,
#endif /* JCVM_INT_SUPPORTED */
  /* 0xB1 */ BC_PUTFIELD_A_W,
  /* 0xB2 */ BC_PUTFIELD_B_W,
  /* 0xB3 */ BC_PUTFIELD_S_W,
#ifdef JCVM_INT_SUPPORTED
  /* 0xB4 */ BC_PUTFIELD_I_W,
#endif /* JCVM_INT_SUPPORTED */
  /* 0xB5 */ BC_PUTFIELD_A_THIS,
  /* 0xB6 */ BC_PUTFIELD_B_THIS,
  /* 0xB7 */ BC_PUTFIELD_S_THIS,
#ifdef JCVM_INT_SUPPORTED
  /* 0xB8 */ BC_PUTFIELD_I_THIS,
#endif /* JCVM_INT_SUPPORTED */
  /* 0xFE */ BC_IMPDEP1,
  /* 0xFF */ BC_IMPDEP2,
  BC_UNSUPPORTED
};

static constexpr bytecode_type bytecodes[] = {
    /* 0x00 */ BC_NOP,
    /* 0x01 */ BC_ACONST_NULL,
    /* 0x02 */ BC_SCONST_M1,
    /* 0x03 */ BC_SCONST_0,
    /* 0x04 */ BC_SCONST_1,
    /* 0x05 */ BC_SCONST_2,
    /* 0x06 */ BC_SCONST_3,
    /* 0x07 */ BC_SCONST_4,
    /* 0x08 */ BC_SCONST_5,
#ifdef JCVM_INT_SUPPORTED
    /* 0x09 */ BC_ICONST_M1,
    /* 0x0a */ BC_ICONST_0,
    /* 0x0b */ BC_ICONST_1,
    /* 0x0c */ BC_ICONST_2,
    /* 0x0d */ BC_ICONST_3,
    /* 0x0e */ BC_ICONST_4,
    /* 0x0f */ BC_ICONST_5,
#else  // int type not supported
    /* 0x09 */ BC_UNSUPPORTED,
    /* 0x0a */ BC_UNSUPPORTED,
    /* 0x0b */ BC_UNSUPPORTED,
    /* 0x0c */ BC_UNSUPPORTED,
    /* 0x0d */ BC_UNSUPPORTED,
    /* 0x0e */ BC_UNSUPPORTED,
    /* 0x0f */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x10 */ BC_BSPUSH,
    /* 0x11 */ BC_SSPUSH,
#ifdef JCVM_INT_SUPPORTED
    /* 0x12 */ BC_BIPUSH,
    /* 0x13 */ BC_SIPUSH,
    /* 0x14 */ BC_IIPUSH,
#else  // int type not supported
    /* 0x12 */ BC_UNSUPPORTED,
    /* 0x13 */ BC_UNSUPPORTED,
    /* 0x14 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x15 */ BC_ALOAD,
    /* 0x16 */ BC_SLOAD,
#ifdef JCVM_INT_SUPPORTED
    /* 0x17 */ BC_ILOAD,
#else  // int type not supported
    /* 0x17 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x18 */ BC_ALOAD_0,
    /* 0x19 */ BC_ALOAD_1,
    /* 0x1a */ BC_ALOAD_2,
    /* 0x1b */ BC_ALOAD_3,
    /* 0x1c */ BC_SLOAD_0,
    /* 0x1d */ BC_SLOAD_1,
    /* 0x1e */ BC_SLOAD_2,
    /* 0x1f */ BC_SLOAD_3,
#ifdef JCVM_INT_SUPPORTED
    /* 0x20 */ BC_ILOAD_0,
    /* 0x21 */ BC_ILOAD_1,
    /* 0x22 */ BC_ILOAD_2,
    /* 0x23 */ BC_ILOAD_3,
#else  // int type not supported
    /* 0x20 */ BC_UNSUPPORTED,
    /* 0x21 */ BC_UNSUPPORTED,
    /* 0x22 */ BC_UNSUPPORTED,
    /* 0x23 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x24 */ BC_AALOAD,
    /* 0x25 */ BC_BALOAD,
    /* 0x26 */ BC_SALOAD,
#ifdef JCVM_INT_SUPPORTED
    /* 0x27 */ BC_IALOAD,
#else  // int type not supported
    /* 0x27 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x28 */ BC_ASTORE,
    /* 0x29 */ BC_SSTORE,
#ifdef JCVM_INT_SUPPORTED
    /* 0x2a */ BC_ISTORE,
#else  // int type not supported
    /* 0x2a */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x2b */ BC_ASTORE_0,
    /* 0x2c */ BC_ASTORE_1,
    /* 0x2d */ BC_ASTORE_2,
    /* 0x2e */ BC_ASTORE_3,
    /* 0x2f */ BC_SSTORE_0,
    /* 0x30 */ BC_SSTORE_1,
    /* 0x31 */ BC_SSTORE_2,
    /* 0x32 */ BC_SSTORE_3,
#ifdef JCVM_INT_SUPPORTED
    /* 0x33 */ BC_ISTORE_0,
    /* 0x34 */ BC_ISTORE_1,
    /* 0x35 */ BC_ISTORE_2,
    /* 0x36 */ BC_ISTORE_3,
#else  // int type not supported
    /* 0x33 */ BC_UNSUPPORTED,
    /* 0x34 */ BC_UNSUPPORTED,
    /* 0x35 */ BC_UNSUPPORTED,
    /* 0x36 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x37 */ BC_AASTORE,
    /* 0x38 */ BC_BASTORE,
    /* 0x39 */ BC_SASTORE,
#ifdef JCVM_INT_SUPPORTED
    /* 0x3a */ BC_IASTORE,
#else  // int type not supported
    /* 0x3a */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x3b */ BC_POP,
    /* 0x3c */ BC_POP2,
    /* 0x3d */ BC_DUP,
    /* 0x3e */ BC_DUP2,
    /* 0x3f */ BC_DUP_X,
    /* 0x40 */ BC_SWAP_X,
    /* 0x41 */ BC_SADD,
#ifdef JCVM_INT_SUPPORTED
    /* 0x42 */ BC_IADD,
#else  // int type not supported
    /* 0x42 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x43 */ BC_SSUB,
#ifdef JCVM_INT_SUPPORTED
    /* 0x44 */ BC_ISUB,
#else  // int type not supported
    /* 0x44 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x45 */ BC_SMUL,
#ifdef JCVM_INT_SUPPORTED
    /* 0x46 */ BC_IMUL,
#else  // int type not supported
    /* 0x46 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x47 */ BC_SDIV,
#ifdef JCVM_INT_SUPPORTED
    /* 0x48 */ BC_IDIV,
#else  // int type not supported
    /* 0x48 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x49 */ BC_SREM,
#ifdef JCVM_INT_SUPPORTED
    /* 0x4a */ BC_IREM,
#else  // int type not supported
    /* 0x4a */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x4b */ BC_SNEG,
#ifdef JCVM_INT_SUPPORTED
    /* 0x4c */ BC_INEG,
#else  // int type not supported
    /* 0x4c */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x4d */ BC_SSHL,
#ifdef JCVM_INT_SUPPORTED
    /* 0x4e */ BC_ISHL,
#else  // int type not supported
    /* 0x4e */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x4f */ BC_SSHR,
#ifdef JCVM_INT_SUPPORTED
    /* 0x50 */ BC_ISHR,
#else  // int type not supported
    /* 0x50 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x51 */ BC_SUSHR,
#ifdef JCVM_INT_SUPPORTED
    /* 0x52 */ BC_IUSHR,
#else  // int type not supported
    /* 0x52 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x53 */ BC_SAND,
#ifdef JCVM_INT_SUPPORTED
    /* 0x54 */ BC_IAND,
#else  // int type not supported
    /* 0x54 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x55 */ BC_SOR,
#ifdef JCVM_INT_SUPPORTED
    /* 0x56 */ BC_IOR,
#else  // int type not supported
    /* 0x56 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x57 */ BC_SXOR,
#ifdef JCVM_INT_SUPPORTED
    /* 0x58 */ BC_IXOR,
#else  // int type not supported
    /* 0x58 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x59 */ BC_SINC,
#ifdef JCVM_INT_SUPPORTED
    /* 0x5a */ BC_IINC,
#else  // int type not supported
    /* 0x5a */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x5b */ BC_S2B,
#ifdef JCVM_INT_SUPPORTED
    /* 0x5c */ BC_S2I,
    /* 0x5d */ BC_I2B,
    /* 0x5e */ BC_I2S,
    /* 0x5f */ BC_ICMP,
#else  // int type not supported
    /* 0x5c */ BC_UNSUPPORTED,
    /* 0x5d */ BC_UNSUPPORTED,
    /* 0x5e */ BC_UNSUPPORTED,
    /* 0x5f */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x60 */ BC_IFEQ,
    /* 0x61 */ BC_IFNE,
    /* 0x62 */ BC_IFLT,
    /* 0x63 */ BC_IFGE,
    /* 0x64 */ BC_IFGT,
    /* 0x65 */ BC_IFLE,
    /* 0x66 */ BC_IFNULL,
    /* 0x67 */ BC_IFNONNULL,
    /* 0x68 */ BC_IF_ACMPEQ,
    /* 0x69 */ BC_IF_ACMPNE,
    /* 0x6a */ BC_IF_SCMPEQ,
    /* 0x6b */ BC_IF_SCMPNE,
    /* 0x6c */ BC_IF_SCMPLT,
    /* 0x6d */ BC_IF_SCMPGE,
    /* 0x6e */ BC_IF_SCMPGT,
    /* 0x6f */ BC_IF_SCMPLE,
    /* 0x70 */ BC_GOTO,
    /* 0x71 */ BC_JSR,
    /* 0x72 */ BC_RET,
    /* 0x73 */ BC_STABLESWITCH,
#ifdef JCVM_INT_SUPPORTED
    /* 0x74 */ BC_ITABLESWITCH,
#else  // int type not supported
    /* 0x76 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x75 */ BC_SLOOKUPSWITCH,
#ifdef JCVM_INT_SUPPORTED
    /* 0x76 */ BC_ILOOKUPSWITCH,
#else  // int type not supported
    /* 0x76 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x77 */ BC_ARETURN,
    /* 0x78 */ BC_SRETURN,
#ifdef JCVM_INT_SUPPORTED
    /* 0x79 */ BC_IRETURN,
#else  // int type not supported
    /* 0x79 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x7a */ BC_RETURN,
    /* 0x7b */ BC_GETSTATIC_A,
    /* 0x7c */ BC_GETSTATIC_B,
    /* 0x7d */ BC_GETSTATIC_S,
#ifdef JCVM_INT_SUPPORTED
    /* 0x7e */ BC_GETSTATIC_I,
#else  // int type not supported
    /* 0x7e */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x7f */ BC_PUTSTATIC_A,
    /* 0x80 */ BC_PUTSTATIC_B,
    /* 0x81 */ BC_PUTSTATIC_S,
#ifdef JCVM_INT_SUPPORTED
    /* 0x82 */ BC_PUTSTATIC_I,
#else  // int type not supported
    /* 0x82 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x83 */ BC_GETFIELD_A,
    /* 0x84 */ BC_GETFIELD_B,
    /* 0x85 */ BC_GETFIELD_S,
#ifdef JCVM_INT_SUPPORTED
    /* 0x86 */ BC_GETFIELD_I,
#else  // int type not supported
    /* 0x86 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x87 */ BC_PUTFIELD_A,
    /* 0x88 */ BC_PUTFIELD_B,
    /* 0x89 */ BC_PUTFIELD_S,
#ifdef JCVM_INT_SUPPORTED
    /* 0x8a */ BC_PUTFIELD_I,
#else  // int type not supported
    /* 0x8a */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x8b */ BC_INVOKEVIRTUAL,
    /* 0x8c */ BC_INVOKESPECIAL,
    /* 0x8d */ BC_INVOKESTATIC,
    /* 0x8e */ BC_INVOKEINTERFACE,
    /* 0x8f */ BC_NEW,
    /* 0x90 */ BC_NEWARRAY,
    /* 0x91 */ BC_ANEWARRAY,
    /* 0x92 */ BC_ARRAYLENGTH,
    /* 0x93 */ BC_ATHROW,
    /* 0x94 */ BC_CHECKCAST,
    /* 0x95 */ BC_INSTANCEOF,
    /* 0x96 */ BC_SINC_W,
#ifdef JCVM_INT_SUPPORTED
    /* 0x97 */ BC_IINC_W,
#else  // int type not supported
    /* 0x97 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0x98 */ BC_IFEQ_W,
    /* 0x99 */ BC_IFNE_W,
    /* 0x9a */ BC_IFLT_W,
    /* 0x9b */ BC_IFGE_W,
    /* 0x9c */ BC_IFGT_W,
    /* 0x9d */ BC_IFLE_W,
    /* 0x9e */ BC_IFNULL_W,
    /* 0x9f */ BC_IFNONNULL_W,
    /* 0xa0 */ BC_IF_ACMPEQ_W,
    /* 0xa1 */ BC_IF_ACMPNE_W,
    /* 0xa2 */ BC_IF_SCMPEQ_W,
    /* 0xa3 */ BC_IF_SCMPNE_W,
    /* 0xa4 */ BC_IF_SCMPLT_W,
    /* 0xa5 */ BC_IF_SCMPGE_W,
    /* 0xa6 */ BC_IF_SCMPGT_W,
    /* 0xa7 */ BC_IF_SCMPLE_W,
    /* 0xa8 */ BC_GOTO_W,
    /* 0xa9 */ BC_GETFIELD_A_W,
    /* 0xaa */ BC_GETFIELD_B_W,
    /* 0xab */ BC_GETFIELD_S_W,
#ifdef JCVM_INT_SUPPORTED
    /* 0xac */ BC_GETFIELD_I_W,
#else  // int type not supported
    /* 0xac */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0xad */ BC_GETFIELD_A_THIS,
    /* 0xae */ BC_GETFIELD_B_THIS,
    /* 0xaf */ BC_GETFIELD_S_THIS,
#ifdef JCVM_INT_SUPPORTED
    /* 0xb0 */ BC_GETFIELD_I_THIS,
#else  // int type not supported
    /* 0xb0 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0xb1 */ BC_PUTFIELD_A_W,
    /* 0xb2 */ BC_PUTFIELD_B_W,
    /* 0xb3 */ BC_PUTFIELD_S_W,
#ifdef JCVM_INT_SUPPORTED
    /* 0xb4 */ BC_PUTFIELD_I_W,
#else  // int type not supported
    /* 0xb4 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0xb5 */ BC_PUTFIELD_A_THIS,
    /* 0xb6 */ BC_PUTFIELD_B_THIS,
    /* 0xb7 */ BC_PUTFIELD_S_THIS,
#ifdef JCVM_INT_SUPPORTED
    /* 0xb8 */ BC_PUTFIELD_I_THIS,
#else  // int type not supported
    /* 0xb8 */ BC_UNSUPPORTED,
#endif /* JCVM_INT_SUPPORTED */
    /* 0xb9 */ BC_UNSUPPORTED,
    /* 0xba */ BC_UNSUPPORTED,
    /* 0xbb */ BC_UNSUPPORTED,
    /* 0xbc */ BC_UNSUPPORTED,
    /* 0xbd */ BC_UNSUPPORTED,
    /* 0xbe */ BC_UNSUPPORTED,
    /* 0xbf */ BC_UNSUPPORTED,
    /* 0xc0 */ BC_UNSUPPORTED,
    /* 0xc1 */ BC_UNSUPPORTED,
    /* 0xc2 */ BC_UNSUPPORTED,
    /* 0xc3 */ BC_UNSUPPORTED,
    /* 0xc4 */ BC_UNSUPPORTED,
    /* 0xc5 */ BC_UNSUPPORTED,
    /* 0xc6 */ BC_UNSUPPORTED,
    /* 0xc7 */ BC_UNSUPPORTED,
    /* 0xc8 */ BC_UNSUPPORTED,
    /* 0xc9 */ BC_UNSUPPORTED,
    /* 0xca */ BC_UNSUPPORTED,
    /* 0xcb */ BC_UNSUPPORTED,
    /* 0xcc */ BC_UNSUPPORTED,
    /* 0xcd */ BC_UNSUPPORTED,
    /* 0xce */ BC_UNSUPPORTED,
    /* 0xcf */ BC_UNSUPPORTED,
    /* 0xd0 */ BC_UNSUPPORTED,
    /* 0xd1 */ BC_UNSUPPORTED,
    /* 0xd2 */ BC_UNSUPPORTED,
    /* 0xd3 */ BC_UNSUPPORTED,
    /* 0xd4 */ BC_UNSUPPORTED,
    /* 0xd5 */ BC_UNSUPPORTED,
    /* 0xd6 */ BC_UNSUPPORTED,
    /* 0xd7 */ BC_UNSUPPORTED,
    /* 0xd8 */ BC_UNSUPPORTED,
    /* 0xd9 */ BC_UNSUPPORTED,
    /* 0xda */ BC_UNSUPPORTED,
    /* 0xdb */ BC_UNSUPPORTED,
    /* 0xdc */ BC_UNSUPPORTED,
    /* 0xdd */ BC_UNSUPPORTED,
    /* 0xde */ BC_UNSUPPORTED,
    /* 0xdf */ BC_UNSUPPORTED,
    /* 0xe0 */ BC_UNSUPPORTED,
    /* 0xe1 */ BC_UNSUPPORTED,
    /* 0xe2 */ BC_UNSUPPORTED,
    /* 0xe3 */ BC_UNSUPPORTED,
    /* 0xe4 */ BC_UNSUPPORTED,
    /* 0xe5 */ BC_UNSUPPORTED,
    /* 0xe6 */ BC_UNSUPPORTED,
    /* 0xe7 */ BC_UNSUPPORTED,
    /* 0xe8 */ BC_UNSUPPORTED,
    /* 0xe9 */ BC_UNSUPPORTED,
    /* 0xea */ BC_UNSUPPORTED,
    /* 0xeb */ BC_UNSUPPORTED,
    /* 0xec */ BC_UNSUPPORTED,
    /* 0xed */ BC_UNSUPPORTED,
    /* 0xee */ BC_UNSUPPORTED,
    /* 0xef */ BC_UNSUPPORTED,
    /* 0xf0 */ BC_UNSUPPORTED,
    /* 0xf1 */ BC_UNSUPPORTED,
    /* 0xf2 */ BC_UNSUPPORTED,
    /* 0xf3 */ BC_UNSUPPORTED,
    /* 0xf4 */ BC_UNSUPPORTED,
    /* 0xf5 */ BC_UNSUPPORTED,
    /* 0xf6 */ BC_UNSUPPORTED,
    /* 0xf7 */ BC_UNSUPPORTED,
    /* 0xf8 */ BC_UNSUPPORTED,
    /* 0xf9 */ BC_UNSUPPORTED,
    /* 0xfa */ BC_UNSUPPORTED,
    /* 0xfb */ BC_UNSUPPORTED,
    /* 0xfc */ BC_UNSUPPORTED,
    /* 0xfd */ BC_UNSUPPORTED,
    /* 0xfe */ BC_IMPDEP1,
    /* 0xff */ BC_IMPDEP2,
};

} // namespace jcvm

#endif /* _BYTECODE_VALUES_HPP */
