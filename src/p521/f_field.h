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

#include <string.h>
#include "constant_time.h"

#include "p521.h"
#define FIELD_BITS           521
#define field_t              p521_t
#define field_mul            p521_mul
#define field_sqr            p521_sqr
#define field_add_RAW        p521_add_RAW
#define field_sub_RAW        p521_sub_RAW
#define field_mulw           p521_mulw
#define field_bias           p521_bias
#define field_isr            p521_isr
#define field_inverse        p521_inverse
#define field_weak_reduce    p521_weak_reduce
#define field_strong_reduce  p521_strong_reduce
#define field_serialize      p521_serialize
#define field_deserialize    p521_deserialize

#endif /* __F_FIELD_H__ */
