/*
 *  Copyright (c) 2014, Oculus VR, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

/// \file DS_RangeList.h
/// \internal
/// \brief A queue implemented as a linked list.
///

#ifndef __RANGE_LIST_H
#define __RANGE_LIST_H

#include "DS_OrderedList.h"
#include "BitStream.h"
#include "RakMemoryOverride.h"
#include "RakAssert.h"

namespace DataStructures
{
	template <class range_type>
	struct RangeNode
	{
		RangeNode() {}
		~RangeNode() {}
		RangeNode(range_type min, range_type max)
		{
			minIndex = min;
			maxIndex = max;
		}
		range_type minIndex;
		range_type maxIndex;
	};

	template <class range_type>
	int RangeNodeComp(const range_type &a, const RangeNode<range_type> &b)
	{
		if (a < b.minIndex)
			return -1;
		if (a == b.minIndex)
			return 0;
		return 1;
	}

	template <class range_type>
	class RAK_DLL_EXPORT RangeList
	{
	public:
		RangeList();
		~RangeList();
		void Insert(range_type index);
		void Clear(void);
		unsigned Size(void) const;
		unsigned RangeSum(void) const;
		RakNet::BitSize_t Serialize(RakNet::BitStream *in, RakNet::BitSize_t maxBits, bool clearSerialized);
		bool Deserialize(RakNet::BitStream *out);

		DataStructures::OrderedList<range_type, RangeNode<range_type>, RangeNodeComp<range_type>> ranges;
	};

	template <class range_type>
	RakNet::BitSize_t RangeList<range_type>::Serialize(RakNet::BitStream *in, RakNet::BitSize_t maxBits, bool clearSerialized)
	{
		RakAssert(ranges.Size() < (unsigned short)-1);

		RakNet::BitStream tempBS;
		RakNet::BitSize_t bitsWritten = 0;
		unsigned short countWritten = 0;

		for (unsigned int i = 0; i < ranges.Size(); ++i)
		{
			auto range = ranges[i];

			if ((sizeof(unsigned short) * 8 + bitsWritten + sizeof(range_type) * 8 * 2 + 1) > maxBits)
			{
				break;
			}

			tempBS.Write<unsigned char>(range.minIndex == range.maxIndex);

			tempBS.Write<range_type>(range.minIndex);
			bitsWritten += sizeof(range_type) * 8 + 8;

			if (range.minIndex != range.maxIndex)
			{
				tempBS.Write(range.maxIndex);
				bitsWritten += sizeof(range_type) * 8;
			}

			countWritten++;
		}

		in->AlignWriteToByteBoundary();
		const auto before = in->GetWriteOffset();
		in->Write(countWritten);
		bitsWritten += in->GetWriteOffset() - before;

		in->Write(&tempBS, tempBS.GetNumberOfBitsUsed());

		if (clearSerialized && countWritten)
		{
			unsigned rangeSize = ranges.Size();
			for (unsigned i = 0; i < rangeSize - countWritten; ++i)
			{
				ranges[i] = ranges[i + countWritten];
			}
			ranges.RemoveFromEnd(countWritten);
		}

		return bitsWritten;
	}

	template <class range_type>
	bool RangeList<range_type>::Deserialize(RakNet::BitStream *out)
	{
		ranges.Clear(true, _FILE_AND_LINE_);

		out->AlignReadToByteBoundary();

		unsigned short count;
		if (!out->Read<unsigned short>(count))
		{
			return false;
		}

		for (unsigned short i = 0; i < count; ++i)
		{
			unsigned char maxEqualToMin;
			if (!out->Read<unsigned char>(maxEqualToMin))
			{
				return false;
			}

			range_type min;
			if (!out->Read<range_type>(min))
			{
				return false;
			}

			range_type max;
			if (!maxEqualToMin)
			{
				if (!out->Read<range_type>(max))
				{
					return false;
				}

				if (max < min)
				{
					return false;
				}
			}
			else
			{
				max = min;
			}

			ranges.InsertAtEnd({min, max}, _FILE_AND_LINE_);
		}

		return true;
	}

	template <class range_type>
	RangeList<range_type>::RangeList()
	{
		RangeNodeComp<range_type>(0, RangeNode<range_type>());
	}

	template <class range_type>
	RangeList<range_type>::~RangeList()
	{
		Clear();
	}

	template <class range_type>
	void RangeList<range_type>::Insert(range_type index)
	{
		if (ranges.Size() == 0)
		{
			ranges.Insert(index, RangeNode<range_type>(index, index), true, _FILE_AND_LINE_);
			return;
		}

		bool objectExists;
		unsigned insertionIndex = ranges.GetIndexFromKey(index, &objectExists);
		if (insertionIndex == ranges.Size())
		{
			if (index == ranges[insertionIndex - 1].maxIndex + (range_type)1)
				ranges[insertionIndex - 1].maxIndex++;
			else if (index > ranges[insertionIndex - 1].maxIndex + (range_type)1)
			{
				// Insert at end
				ranges.Insert(index, RangeNode<range_type>(index, index), true, _FILE_AND_LINE_);
			}

			return;
		}

		if (index < ranges[insertionIndex].minIndex - (range_type)1)
		{
			// Insert here
			ranges.InsertAtIndex(RangeNode<range_type>(index, index), insertionIndex, _FILE_AND_LINE_);

			return;
		}
		else if (index == ranges[insertionIndex].minIndex - (range_type)1)
		{
			// Decrease minIndex and join left
			ranges[insertionIndex].minIndex--;
			if (insertionIndex > 0 && ranges[insertionIndex - 1].maxIndex + (range_type)1 == ranges[insertionIndex].minIndex)
			{
				ranges[insertionIndex - 1].maxIndex = ranges[insertionIndex].maxIndex;
				ranges.RemoveAtIndex(insertionIndex);
			}

			return;
		}
		else if (index >= ranges[insertionIndex].minIndex && index <= ranges[insertionIndex].maxIndex)
		{
			// Already exists
			return;
		}
		else if (index == ranges[insertionIndex].maxIndex + (range_type)1)
		{
			// Increase maxIndex and join right
			ranges[insertionIndex].maxIndex++;
			if (insertionIndex < ranges.Size() - 1 && ranges[insertionIndex + (range_type)1].minIndex == ranges[insertionIndex].maxIndex + (range_type)1)
			{
				ranges[insertionIndex + 1].minIndex = ranges[insertionIndex].minIndex;
				ranges.RemoveAtIndex(insertionIndex);
			}

			return;
		}
	}

	template <class range_type>
	void RangeList<range_type>::Clear(void)
	{
		ranges.Clear(true, _FILE_AND_LINE_);
	}

	template <class range_type>
	unsigned RangeList<range_type>::Size(void) const
	{
		return ranges.Size();
	}

	template <class range_type>
	unsigned RangeList<range_type>::RangeSum(void) const
	{
		unsigned sum = 0, i;
		for (i = 0; i < ranges.Size(); i++)
			sum += ranges[i].maxIndex - ranges[i].minIndex + 1;
		return sum;
	}

}

#endif
