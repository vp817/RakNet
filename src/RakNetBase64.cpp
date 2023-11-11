/*
 *  Copyright (c) 2014, Oculus VR, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "RakNetBase64.h"
#include "RakMemoryOverride.h"

const char *Base64Map(void) { return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; }

// 3/17/2013 must be unsigned char or else it will use negative indices
int Base64Encoding(const unsigned char *inputData, int dataLength, char *outputData)
{
	// http://en.wikipedia.org/wiki/Base64

	int outputOffset, charCount;
	int write3Count;
	outputOffset = 0;
	charCount = 0;
	int j;

	write3Count = dataLength / 3;
	for (j = 0; j < write3Count; j++)
	{
		// 6 leftmost bits from first byte, shifted to bits 7,8 are 0
		outputData[outputOffset++] = Base64Map()[inputData[j * 3 + 0] >> 2];
		if ((++charCount % 76) == 0)
		{
			outputData[outputOffset++] = '\r';
			outputData[outputOffset++] = '\n';
			charCount = 0;
		}

		// Remaining 2 bits from first byte, placed in position, and 4 high bits from the second byte, masked to ignore bits 7,8
		outputData[outputOffset++] = Base64Map()[((inputData[j * 3 + 0] << 4) | (inputData[j * 3 + 1] >> 4)) & 63];
		if ((++charCount % 76) == 0)
		{
			outputData[outputOffset++] = '\r';
			outputData[outputOffset++] = '\n';
			charCount = 0;
		}

		// 4 low bits from the second byte and the two high bits from the third byte, masked to ignore bits 7,8
		outputData[outputOffset++] = Base64Map()[((inputData[j * 3 + 1] << 2) | (inputData[j * 3 + 2] >> 6)) & 63]; // Third 6 bits
		if ((++charCount % 76) == 0)
		{
			outputData[outputOffset++] = '\r';
			outputData[outputOffset++] = '\n';
			charCount = 0;
		}

		// Last 6 bits from the third byte, masked to ignore bits 7,8
		outputData[outputOffset++] = Base64Map()[inputData[j * 3 + 2] & 63];
		if ((++charCount % 76) == 0)
		{
			outputData[outputOffset++] = '\r';
			outputData[outputOffset++] = '\n';
			charCount = 0;
		}
	}

	if (dataLength % 3 == 1)
	{
		// One input byte remaining
		outputData[outputOffset++] = Base64Map()[inputData[j * 3 + 0] >> 2];
		if ((++charCount % 76) == 0)
		{
			outputData[outputOffset++] = '\r';
			outputData[outputOffset++] = '\n';
			charCount = 0;
		}

		// Remaining 2 bits from first byte, placed in position, and 4 high bits from the second byte, masked to ignore bits 7,8
		outputData[outputOffset++] = Base64Map()[((inputData[j * 3 + 0] << 4) | (inputData[j * 3 + 1] >> 4)) & 63];
		if ((++charCount % 76) == 0)
		{
			outputData[outputOffset++] = '\r';
			outputData[outputOffset++] = '\n';
			charCount = 0;
		}

		// Pad with two equals
		outputData[outputOffset++] = '=';
		outputData[outputOffset++] = '=';
	}
	else if (dataLength % 3 == 2)
	{
		// Two input bytes remaining

		// 6 leftmost bits from first byte, shifted to bits 7,8 are 0
		outputData[outputOffset++] = Base64Map()[inputData[j * 3 + 0] >> 2];
		if ((++charCount % 76) == 0)
		{
			outputData[outputOffset++] = '\r';
			outputData[outputOffset++] = '\n';
			charCount = 0;
		}

		// Remaining 2 bits from first byte, placed in position, and 4 high bits from the second byte, masked to ignore bits 7,8
		outputData[outputOffset++] = Base64Map()[((inputData[j * 3 + 0] << 4) | (inputData[j * 3 + 1] >> 4)) & 63];
		if ((++charCount % 76) == 0)
		{
			outputData[outputOffset++] = '\r';
			outputData[outputOffset++] = '\n';
			charCount = 0;
		}

		// 4 low bits from the second byte, followed by 00
		outputData[outputOffset++] = Base64Map()[(inputData[j * 3 + 1] << 2) & 63]; // Third 6 bits
		if ((++charCount % 76) == 0)
		{
			outputData[outputOffset++] = '\r';
			outputData[outputOffset++] = '\n';
			charCount = 0;
		}

		// Pad with one equal
		outputData[outputOffset++] = '=';
		// outputData[outputOffset++]='=';
	}

	// Append \r\n
	outputData[outputOffset++] = '\r';
	outputData[outputOffset++] = '\n';
	outputData[outputOffset] = 0;

	return outputOffset;
}

int Base64Decoding(const unsigned char *inputData, int dataLength, unsigned char **outputData)
{
	if (dataLength <= 0)
		return 0;

	unsigned char base64Index[256] = {
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62, 255, 255, 255, 63,
		52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255, 255, 255, 255, 255,
		255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
		15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255,
		255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
		41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255};

	int outputLengthBits = 6 * dataLength / 8;
	int outputLength = outputLengthBits;

	// Check if padding is present
	if (dataLength > 1 && inputData[dataLength - 1] == '=')
	{
		outputLength--;
		if (dataLength > 2 && inputData[dataLength - 2] == '=')
		{
			outputLength--;
		}
	}

	*outputData = (unsigned char *)rakMalloc_Ex(outputLength, _FILE_AND_LINE_);
	int outputDataOffset = 0;

	unsigned char inTuple[4];
	int inTupleCount = 0;

	for (int i = 0; i < dataLength; i++)
	{
		unsigned char inChar = inputData[i];
		if (inChar == '\r' || inChar == '\n')
			continue;
		unsigned char index = base64Index[inChar];
		if (index != 255)
		{
			// Valid base64 character
			inTuple[inTupleCount++] = index;
			if (inTupleCount == 4)
			{
				// Decode the 4-tuple
				(*outputData)[outputDataOffset++] = (inTuple[0] << 2) | (inTuple[1] >> 4);
				(*outputData)[outputDataOffset++] = (inTuple[1] << 4) | (inTuple[2] >> 2);
				(*outputData)[outputDataOffset++] = (inTuple[2] << 6) | inTuple[3];
				inTupleCount = 0;
			}
		}
	}

	if (inTupleCount > 1)
	{
		// The remaining base64 characters form a valid tuple
		(*outputData)[outputDataOffset++] = (inTuple[0] << 2) | (inTuple[1] >> 4);
	}
	if (inTupleCount > 2)
	{
		(*outputData)[outputDataOffset++] = (inTuple[1] << 4) | (inTuple[2] >> 2);
	}

	return outputDataOffset;
}

int Base64Encoding(const unsigned char *inputData, int dataLength, char **outputData)
{
	*outputData = (char *)rakMalloc_Ex(dataLength * 2 + 6, _FILE_AND_LINE_);
	return Base64Encoding(inputData, dataLength, *outputData);
}
