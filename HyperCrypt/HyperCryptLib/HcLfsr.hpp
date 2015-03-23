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

#ifndef __HCLFSR_HPP__
#define __HCLFSR_HPP__

#include <stdint.h>

class HcLfsr
{
   public:
      HcLfsr (uint32_t max_bits);

      static uint32_t getMinSize (void);
      static uint32_t getMaxSize (void);

      uint64_t getSpec (void);
      bool setSpec (uint64_t spec);

      bool reset (uint32_t size, uint32_t seed, int variant);

      uint32_t getNext (void);
      bool fillNext (uint32_t* buffer, uint32_t count);

   private:
      uint32_t m_lfsr;
      uint32_t m_seed;
      uint32_t m_poly;
      uint32_t m_max_bits;
};

#endif