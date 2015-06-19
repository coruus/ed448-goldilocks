/**
 * @file f_field.h
 * @brief Field-specific code.
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 */
#ifndef __F_FIELD_H__
#define __F_FIELD_H__ 1

#include "constant_time.h"
#include <string.h>

#include "p25519.h"
#define FIELD_LIT_LIMB_BITS  51
#define FIELD_BITS           255
#define field_t              p255_t
#define field_mul            p255_mul
#define field_sqr            p255_sqr
#define field_add_RAW        p255_add_RAW
#define field_sub_RAW        p255_sub_RAW
#define field_mulw           p255_mulw
#define field_bias           p255_bias
#define field_isr            p255_isr
#define field_inverse        p255_inverse
#define field_weak_reduce    p255_weak_reduce
#define field_strong_reduce  p255_strong_reduce
#define field_serialize      p255_serialize
#define field_deserialize    p255_deserialize

#endif /* __F_FIELD_H__ */
