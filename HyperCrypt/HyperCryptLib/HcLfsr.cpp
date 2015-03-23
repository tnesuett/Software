/*
   The MIT License(MIT)

   Copyright(c) 2015 Jamal Benbrahim

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files(the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions :

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
*/

#include <stdint.h>
#include <random>

#include <vector>

#include "HcLfsr.hpp"

//#define VERBOSE

#define MIN_BITS 15
#define MAX_BITS 28
#define MAX_POLIES (MAX_BITS - MIN_BITS + 1)

/*
   derived from:
   Error Correction Coding: Mathematical Methods and Algorithms by Todd K. Moon, Utah State University published by Wiley, 2005 756+xliii pages, plus Web page. (ISBN 0-471-64800-0)
*/
static const uint32_t poly_tables[MAX_POLIES][16] =
{
	// 15 Bits
	{0x00008423, 0x0000900B, 0x00008437, 0x000088C7, 0x000080CF, 0x0000FFFD, 0x00008729, 0x0000903D, 0x00008431, 0x000099D5, 0x000086A9, 0x00000000},
	// 16 Bits
	{0x0001100B, 0x000138CB, 0x000136C3, 0x00018E47, 0x00018F57, 0x00018CEF, 0x000103DD, 0x00017481, 0x0001450B, 0x0001706D, 0x0001846F, 0x00011085, 0x00018BB7, 0x00013C47, 0x00000000},
	// 17 Bits
	{0x0002000F, 0x00020119, 0x0002AAA9, 0x0002104F, 0x000201D9, 0x000212DD, 0x000248AF, 0x0003000B, 0x0002076D, 0x0002AAD7, 0x0002123F, 0x00000000},
	// 18 Bits
	{0x000404A1, 0x00048025, 0x00040107, 0x00040609, 0x00042051, 0x00048205, 0x0004003F, 0x000402F1, 0x00040377, 0x000403D7, 0x000405FF, 0x00000000},
	// 19 Bits
	{0x00080027, 0x000801A1, 0x00080321, 0x00080047, 0x0008003F, 0x0008006F, 0x0008007D, 0x000800AF, 0x000801BF, 0x000801DF, 0x0008036F, 0x0008039F, 0x00080BFD, 0x00080DBF, 0x00000000},
	// 20 Bits
	{0x00100229, 0x0010094D, 0x00180019, 0x0012449D, 0x00000000},
	// 21 Bits
	{0x00204085, 0x00202025, 0x002040CD, 0x0020019D, 0x0020863D, 0x002050DD, 0x0020045D, 0x003C003D, 0x00000000},
	// 22 Bits
	{0x00400223, 0x00550057, 0x00420287, 0x00423187, 0x0040708F, 0x00000000},
	// 23 Bits
	{0x00820821, 0x00800033, 0x00801031, 0x00A000A1, 0x00812069, 0x00800CE1, 0x00820B33, 0x008086B9, 0x00852925, 0x00000000},
	// 24 Bits
	{0x01000087, 0x01554BB1, 0x012FE633, 0x00000000},
	// 25 Bits
	{0x0200000F, 0x02100029, 0x02001019, 0x0202040F, 0x02A802A9, 0x02041879, 0x0211082F, 0x02000B5D, 0x020019D9, 0x00000000},
	// 26 Bits
	{0x04000047, 0x04611D3B, 0x0409EBED, 0x04592BB7, 0x052368D3, 0x04ECEF65, 0x0425BB79, 0x00000000},
	// 27 Bits
	{0x08000027, 0x08040E39, 0x08402879, 0x0909118F, 0x0AA02BEF, 0x0ABD4599, 0x0842E043, 0x09292A79, 0x00000000},
	// 28 Bits
	{0x11111119, 0x10002A29, 0x10400C19, 0x100A844D, 0x10070239, 0x00000000}
};

#pragma pack(1)

union LfsrSpec
{
   struct
   {
      uint32_t seed;
      uint32_t poly;
   } s;
   uint64_t spec;
};

#pragma pack ()

static std::vector<uint32_t> polies [MAX_POLIES];
static bool initialized = false;

#define NEXT_LFSR(_lfsr, _poly) _lfsr = (_lfsr & 1) ? ((_lfsr >> 1) ^ _poly) : (_lfsr >> 1);

// Return a random number between min and max, inclusive.
static int get_random (int min, int max)
{
   std::random_device rd;
   std::mt19937_64 gen(rd());
   std::uniform_int_distribution<> dist(min, max);

   return dist (gen);
}

// Verify that the specified polynomial generates a unique sequence from 1 to (1 << bit_count) - 1
static bool verify_poly (uint32_t poly, int bit_count, uint32_t seed)
{
   size_t max_period = (1 << bit_count) - 1;
   seed &= max_period;
   uint32_t lfsr = seed;

   std::vector<uint32_t> vals;
   vals.resize (1 << bit_count, 0xFFFFFFFF);

   size_t period = 0;
   uint32_t* val_buf = &vals[0];

   do
   {
      if (lfsr > max_period)
      {
         break;
      }

      val_buf[lfsr] = lfsr;

      NEXT_LFSR (lfsr, poly);

      ++period;

   } while ((lfsr != seed) && (period < max_period));

   // The LFSR should not generate a value of 0.  So, set the 0th slot.
   vals[0] = 0;

   // Make sure all the slots have been set. 
   for (size_t i = 0; i < vals.size(); ++i)
   {
      if (0xFFFFFFFF == val_buf[i])
      {
#ifdef VERBOSE
         printf ("%d:%s\n", __LINE__, __FUNCTION__);
#endif
         return false;
      }
   }

   return true;
}

// Prep the polies for the algorithm and generate derived polies.  Optionally verify that the poly generates unique values.
static bool create_polies (bool verify, uint32_t max_bits)
{
   initialized = false;

   uint32_t max_polies = max_bits - MIN_BITS + 1;

   for (uint32_t i = 0; i < max_polies; ++i)
   {
      polies[i].clear ();
   }

   for (uint32_t i = 0; i < max_polies; ++i)
   {
      const uint32_t* poly_entry = poly_tables[i];

#ifdef VERBOSE
      printf ("Adding polies for: %d bits -- ", i + MIN_BITS);
#endif

      bool reversed = false;

	  while (*poly_entry)
      {
         uint32_t p = 0;

         if (reversed)
         {
            for (uint32_t j = 0; j < (MIN_BITS + i); ++j)
            {
               p <<= 1;
			   p |= (*poly_entry & (1 << j)) ? 1 : 0;
            }
         }
         else
         {
			 p = (*poly_entry >> 1);
         }

		 // Verify the poly using a fixed seed.  Any non-zero seed should work fine.
         if (verify && !verify_poly (p, i + MIN_BITS, 0x12345678))
         {
#ifdef VERBOSE
            printf ("%d:%s - %o - %s\n", __LINE__, __FUNCTION__, *poly_specs, reversed ? "reversed" : "non-reversed");
#endif
            return false;
         }

         polies[i].push_back (p);

#ifdef VERBOSE
         printf ("%d ", polies[i].size ());
#endif

         if (reversed)
         {
            reversed = false;
			++poly_entry;
         }
         else
         {
            reversed = true;
         }
      }

#ifdef VERBOSE
      printf ("\n");
#endif
   }

   initialized = true;

   if (verify)
   {
      uint32_t i;

      for (i = 0; i < max_polies; ++i)
      {
         if (polies[i].empty ())
         {
#ifdef VERBOSE
            printf ("%d:%s\n", __LINE__, __FUNCTION__);
#endif
            return false;
         }
      }

      initialized = (max_polies == i);
   }

   return initialized;
}

HcLfsr::HcLfsr (uint32_t max_bits)
{
   if (!max_bits)
   {
      max_bits = MAX_BITS;
   }

   if (max_bits > MAX_BITS)
   {
      max_bits = MAX_BITS;
   }

   if (max_bits < MIN_BITS)
   {
      max_bits = MIN_BITS;
   }

   m_max_bits = max_bits;
   m_lfsr = 0;
   m_seed = 0;
   m_poly = 0;
}

// Return a 64-bit number that defines the poly and seed used.
uint64_t HcLfsr::getSpec (void)
{
   if (!initialized)
   {
      return 0;
   }

   if (!m_seed || !m_poly)
   {
      return 0;
   }

   LfsrSpec s;

   s.s.seed = m_seed;
   s.s.poly = m_poly;

   return s.spec;
}

// Set the poly and seed to be used by the LFSR.
bool HcLfsr::setSpec (uint64_t spec)
{
   if (!initialized)
   {
      create_polies (false, m_max_bits);
   }

   LfsrSpec s;

   s.spec = spec;

   if (!s.s.poly || !s.s.seed)
   {
      return false;
   }

   m_seed = s.s.seed;
   m_poly = s.s.poly;
   m_lfsr = s.s.seed;

   return true;
}

// Get the minimum poly size.
uint32_t HcLfsr::getMinSize (void)
{
   return (1 << MIN_BITS);
}

// Get the maximum poly side.
uint32_t HcLfsr::getMaxSize (void)
{
   return (1 << MAX_BITS);
}

// Reset the poly sequence.
bool HcLfsr::reset (uint32_t size, uint32_t seed, int variant)
{
   m_poly = 0;

   if (!initialized)
   {
      create_polies (false, m_max_bits);
   }

   if ((size > (1u << m_max_bits)) || (size < getMinSize ()))
   {
      return false;
   }

   int poly_index = -1;

   for (uint32_t i = MIN_BITS; i <= m_max_bits; ++i)
   {
      if ((1u << i) == size)
      {
         poly_index = (int)(i - MIN_BITS);
         break;
      }
   }

   if (-1 == poly_index)
   {
#ifdef VERBOSE
      printf ("%d:%s\n", __LINE__, __FUNCTION__);
#endif
      return false;
   }

   if (!initialized)
   {
      if (!create_polies (false, m_max_bits))
      {
#ifdef VERBOSE
         printf ("%d:%s\n", __LINE__, __FUNCTION__);
#endif
         return false;
      }
   }

   if (variant < 0)
   {
      variant = (uint8_t) get_random (0, (int) polies[poly_index].size () - 1);
   }
   else
   {
      variant = (uint8_t) (variant % polies[poly_index].size ());
   }

   while (!seed)
   {
      seed = get_random (1, (1 << (poly_index + MIN_BITS)) - 1);
   }

   seed &= ((1 << (poly_index + MIN_BITS)) - 1);

   if (!verify_poly (polies[poly_index][variant], poly_index + MIN_BITS, seed))
   {
      return false;
   }

   m_poly = polies[poly_index][variant];
   m_seed = seed;
   m_lfsr = m_seed;

   return true;
}

// Get the next number in the sequence.
uint32_t HcLfsr::getNext (void)
{
   if (!m_poly)
   {
      return 0;
   }

   NEXT_LFSR(m_lfsr, m_poly);

   return m_lfsr;
}

// Fill buffer with the next count sequence numbers.
bool HcLfsr::fillNext (uint32_t* buffer, uint32_t count)
{
   while (count--)
   {
      NEXT_LFSR (m_lfsr, m_poly);
      *buffer++ = m_lfsr;

      if (!m_lfsr)
      {
         return false;
      }
   }

   return true;
}
