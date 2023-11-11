/*
 *  Copyright (c) 2014, Oculus VR, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#ifndef __BASE_64_ENCODER_H
#define __BASE_64_ENCODER_H

#include "Export.h"

extern "C"
{
    /// \brief Returns how many bytes were written.
    // outputData should be at least the size of inputData * 2 + 6
    int Base64Encoding(const unsigned char *inputData, int dataLength, char *outputData);
    /// \brief Returns how many bytes were read.
    // outputData should be at least the size of inputData * 3 / 4 + 1
    int Base64Decoding(const unsigned char *inputData, int maxLength, unsigned char *outputData);
}

extern "C"
{
    const char *Base64Map(void);
}

#endif
