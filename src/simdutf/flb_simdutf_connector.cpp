/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <simdutf.h>
#include <uchar.h>
#include <memory.h>
#include <fluent-bit/simdutf/flb_simdutf_connector.h>

size_t flb_simdutf_connector_validate_utf16le(const char16_t *buf, size_t len)
{
    return simdutf::validate_utf16le(buf, len);
}

size_t flb_simdutf_connector_validate_utf16be(const char16_t *buf, size_t len)
{
    return simdutf::validate_utf16be(buf, len);
}

size_t flb_simdutf_connector_validate_utf16(const char16_t *buf, size_t len)
{
    return simdutf::validate_utf16(buf, len);
}

size_t flb_simdutf_connector_validate_utf32(const char32_t *buf, size_t len)
{
    return simdutf::validate_utf32(buf, len);
}

size_t flb_simdutf_connector_convert_utf16le_to_utf8(const char16_t *buf, size_t len, char *utf8_output)
{
    size_t expected_utf8words = simdutf::utf8_length_from_utf16le(buf, len);
    utf8_output = (char *)calloc(1, expected_utf8words);

    return simdutf::convert_utf16le_to_utf8(buf, len, utf8_output);
}

size_t flb_simdutf_connector_convert_utf16be_to_utf8(const char16_t *buf, size_t len, char *utf8_output)
{
    size_t expected_utf8words = simdutf::utf8_length_from_utf16be(buf, len);
    utf8_output = (char *)calloc(1, expected_utf8words);

    return simdutf::convert_utf16be_to_utf8(buf, len, utf8_output);
}

size_t flb_simdutf_connector_convert_utf16_to_utf8(const char16_t *buf, size_t len, char *utf8_output)
{
    size_t expected_utf8words = simdutf::utf8_length_from_utf16(buf, len);
    utf8_output = (char *)calloc(1, expected_utf8words);

    return simdutf::convert_utf16be_to_utf8(buf, len, utf8_output);
}

size_t flb_simdutf_connector_convert_utf32_to_utf8(const char32_t *buf, size_t len, char *utf8_output)
{
    size_t expected_utf8words = simdutf::utf8_length_from_utf32(buf, len);
    utf8_output = (char *)calloc(1, expected_utf8words);

    return simdutf::convert_utf32_to_utf8(buf, len, utf8_output);
}
