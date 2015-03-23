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

#include "HcEngine.hpp"
#include "HcLfsr.hpp"

#include <stdint.h>
#include <vector>
#include <string>
#include <random>
#include <queue>
#include <iostream>
#include <stdint.h>

#include <boost/filesystem.hpp>
#include <boost/filesystem/convenience.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include "openssl/aes.h"
#include "openssl/rand.h"

enum HcInternalError
{
   HC_INTERNAL_ERROR_BAD_LFSR = -2000,
   HC_INTERNAL_ERROR_CANNOT_RAND_FILL,
   HC_INTERNAL_ERROR_BAD_LFSR_SPECS,
   HC_INTERNAL_ERROR_INVALID_INPUT_SEGMENT_SIZE,
   HC_INTERNAL_ERROR_BAD_LFSR_SEQUENCE,
   HC_INTERNAL_ERROR_BAD_LFSR_FILL,
   HC_INTERNAL_ERROR_UNEXPECTED_IN_FILE_EOF,
   HC_INTERNAL_ERROR_BAD_TEMP_BUFFER,
   HC_INTERNAL_ERROR_CANNOT_STAT_INPUT_FILE,
   HC_INTERNAL_ERROR_CANNOT_SET_LFSR_SPEC,
   HC_INTERNAL_ERROR_CANNOT_RESET_LFSR,
};

#define KEY_VERSION   0x00010000
#define CRYPTO_SCHEME "AES-256"

struct HcKeyData
{
   uint64_t m_lfsr_specs;
   uint32_t m_in_size;
   uint32_t m_out_size;
   uint8_t  m_iv[16];
   uint8_t  m_key[256 / 8];
};

// Convenience macro to call back the user.
#define HC_CALLBACK(_status, _status_data)\
   if (m_callback)\
   {\
      try\
      {\
         m_callback (m_callback_context, _status, (int)(_status_data));\
      }\
      catch (...)\
      {\
         return HC_ERROR_CALLBACK_EXCEPTION;\
      }\
   }

// Private version of the HcEngine.
class HcEnginePrivate : public HcEngine
{
   public:
      HcEnginePrivate (void);
      virtual ~HcEnginePrivate (void);

      virtual unsigned long getMinBlockSize (void);
      virtual unsigned long getMaxBlockSize (void);

      virtual HcStatus encryptFile (unsigned long splits, const char* in_file_path, HcEngineCallback callback, void* context);
      virtual HcStatus decryptFile (unsigned long joins, const char* key_file_path, HcEngineCallback callback, void* context);

   private:
      HcEngineCallback m_callback;
      void* m_callback_context;

      HcLfsr* m_lfsr;

      struct FileSpec
      {
         void clear (void)
         {
            m_file_name.clear();
            m_temp_file_name.clear();
            m_file = 0;
            m_size = 0;
         }

         std::string m_file_name;
         std::string m_temp_file_name;
         FILE* m_file;
         size_t m_size;
      };

      std::vector<FileSpec> m_in_files;
      std::vector<FileSpec> m_out_files;
      FileSpec m_key_file;

      size_t m_in_file_index;
      size_t m_out_file_index;

      std::vector<HcKeyData> m_key;
      std::vector<uint8_t> m_buffer;

   private:
      void cleanUp (void);
      HcStatus adjustStatus (int status);

      bool randFill (void* buffer, size_t size);
      std::string getTempFileName (void);

      int generateKey (int64_t file_size);

      int encryptSegment (HcKeyData& key_data);
      int encryptFile (const char* in_file_path, uint32_t splits);

      int decryptSegment (HcKeyData& key_data);
      int decryptFile (const char* key_file_path, unsigned long joins);

      int keyToXmlFile (const char* key_file_path);
      int xmlFileToKey (const char* key_file_path);

      void hexToString (const void* buffer, int count, std::string& str);
      bool stringToHex (void* buffer, int count, const std::string& str);
};

HcEnginePrivate::HcEnginePrivate (void)
{
   m_lfsr = 0;
   m_callback = 0;
   m_callback_context = 0;
   m_in_file_index = 0;
   m_out_file_index = 0;
   m_key_file.clear ();
}

HcEnginePrivate::~HcEnginePrivate (void)
{
   cleanUp ();
}

unsigned long HcEnginePrivate::getMinBlockSize (void)
{
   return HcLfsr::getMinSize ();
}

unsigned long HcEnginePrivate::getMaxBlockSize (void)
{
   return HcLfsr::getMaxSize ();
}

/*
	Encrypt a file:

	splits - number of segments the encrypted file will be split into.
	in_file_path - the path of the file to be encrypted.
	callback - user callback that is called when certain events happen.
	context - user callback context.
*/
HcStatus HcEnginePrivate::encryptFile (unsigned long splits, const char* in_file_path, HcEngineCallback callback, void* context)
{
   cleanUp ();

   m_callback = callback;
   m_callback_context = context;

   int status = encryptFile (in_file_path, splits);

   cleanUp ();

   return adjustStatus (status);
}

/*
	Decrypt a file:

	joins - number of segments that constitue the encrypted file.
	key_file_path - the path of the key file.
	callback - user callback that is called when certain events happen.
	context - user callback context.
*/
HcStatus HcEnginePrivate::decryptFile(unsigned long joins, const char* key_file_path, HcEngineCallback callback, void* context)
{
   cleanUp ();

   m_callback = callback;
   m_callback_context = context;

   if (!key_file_path || !*key_file_path)
   {
      return HC_ERROR_BAD_KEY_FILE_NAME;
   }

   if (!boost::filesystem::exists(key_file_path))
   {
      return HC_ERROR_CANNOT_OPEN_KEY_FILE;
   }

   int result = xmlFileToKey (key_file_path);

   if (HC_STATUS_OK != result)
   {
      return adjustStatus (result);
   }

   uint32_t max_segment_size = 0;

   for (auto& ke : m_key)
   {
      if (!ke.m_in_size || !ke.m_out_size)
      {
         return HC_ERROR_BAD_KEY;
      }

      if (ke.m_in_size > ke.m_out_size)
      {
         return HC_ERROR_BAD_KEY;
      }

      if (ke.m_out_size > getMaxBlockSize ())
      {
         return HC_ERROR_BAD_KEY;
      }

      HcLfsr lfsr (ke.m_out_size);

      if (!lfsr.setSpec (ke.m_lfsr_specs))
      {
         return HC_ERROR_BAD_KEY;
      }

      if (ke.m_out_size > max_segment_size)
      {
         max_segment_size = ke.m_out_size;
      }
   }

   try
   {
      m_buffer.resize (max_segment_size);
   }
   catch (...)
   {
   }

   if (m_buffer.size () != max_segment_size)
   {
      return HC_ERROR_BLOCK_SIZE_TOO_BIG;
   }

   m_lfsr = new HcLfsr (max_segment_size);

   int status = decryptFile (key_file_path, joins);

   cleanUp ();

   return adjustStatus (status);
}

// Clean up the engine.
void HcEnginePrivate::cleanUp (void)
{
   for (auto& e : m_in_files)
   {
      if (e.m_file)
      {
         fclose (e.m_file);
      }
   }

   m_in_files.clear ();

   for (auto& e : m_out_files)
   {
      if (e.m_file)
      {
         fclose (e.m_file);
      }

      if (!e.m_file_name.empty())
      {
         remove (e.m_file_name.c_str ());
      }

      if (!e.m_temp_file_name.empty())
      {
         remove (e.m_temp_file_name.c_str ());
      }
   }

   m_out_files.clear ();

   if (m_key_file.m_file)
   {
      fclose (m_key_file.m_file);
   }

   if (!m_key_file.m_file_name.empty())
   {
      remove (m_key_file.m_file_name.c_str ());
   }

   if (!m_key_file.m_temp_file_name.empty())
   {
      remove (m_key_file.m_temp_file_name.c_str ());
   }

   m_key_file.clear ();

   if (m_lfsr)
   {
      delete m_lfsr;
      m_lfsr = 0;
   }

   m_key.clear ();

   m_buffer.clear ();

   m_in_file_index = 0;
   m_out_file_index = 0;
}

HcStatus HcEnginePrivate::adjustStatus (int status)
{
   switch (status)
   {
      case HC_ERROR_INVALID_INPUT_FILE:
      case HC_ERROR_CANNOT_OPEN_INPUT_FILE:
      case HC_ERROR_CANNOT_READ_INPUT_FILE:
      case HC_ERROR_BAD_INPUT_FILE_NAME:
      case HC_ERROR_INVALID_OUTPUT_FILE:
      case HC_ERROR_CANNOT_CREATE_OUTPUT_FILE:
      case HC_ERROR_CANNOT_WRITE_OUTPUT_FILE:
      case HC_ERROR_BAD_OUTPUT_FILE_NAME:
      case HC_ERROR_INVALID_KEY_FILE:
      case HC_ERROR_CANNOT_OPEN_KEY_FILE:
      case HC_ERROR_CANNOT_CREATE_KEY_FILE:
      case HC_ERROR_CANNOT_READ_KEY_FILE:
      case HC_ERROR_CANNOT_WRITE_KEY_FILE:
      case HC_ERROR_INVALID_KEY:
      case HC_ERROR_CANNOT_CREATE_KEY:
      case HC_ERROR_BAD_KEY:
      case HC_ERROR_BAD_KEY_FILE_NAME:
      case HC_ERROR_CANNOT_ENCRYPT_SECTION:
      case HC_ERROR_CANNOT_ENCRYPT_FILE:
      case HC_ERROR_CANNOT_DECRYPT_SECTION:
      case HC_ERROR_CANNOT_DECRYPT_FILE:
      case HC_ERROR_CALLBACK_EXCEPTION:
      case HC_ERROR_BLOCK_SIZE_TOO_BIG:
      case HC_ERROR_OUTPUT_FILE_ALREADY_EXISTS:
      case HC_ERROR_KEY_FILE_ALREADY_EXISTS:

      case HC_STATUS_OK:
      case HC_STATUS_KEY_CREATION_START:
      case HC_STATUS_KEY_CREATION_END:
      case HC_STATUS_ENCRYPT_START:
      case HC_STATUS_ENCRYPT_PROGRESS:
      case HC_STATUS_ENCRYPT_END:
      case HC_STATUS_ENCRYPT_SECTION_START:
      case HC_STATUS_ENCRYPT_SECTION_PROGRESS:
      case HC_STATUS_ENCRYPT_SECTION_END:
      case HC_STATUS_DECRYPT_START:
      case HC_STATUS_DECRYPT_PROGRESS:
      case HC_STATUS_DECRYPT_END:
      case HC_STATUS_DECRYPT_SECTION_START:
      case HC_STATUS_DECRYPT_SECTION_PROGRESS:
      case HC_STATUS_DECRYPT_SECTION_END:
      case HC_STATUS_ANALYSE_FILE_START:
      case HC_STATUS_ANALYSE_FILE_END:
      case HC_STATUS_DONE:
         break;

      case HC_INTERNAL_ERROR_BAD_LFSR:
      case HC_INTERNAL_ERROR_CANNOT_RAND_FILL:
      case HC_INTERNAL_ERROR_BAD_LFSR_SPECS:
      case HC_INTERNAL_ERROR_INVALID_INPUT_SEGMENT_SIZE:
      case HC_INTERNAL_ERROR_BAD_LFSR_SEQUENCE:
      case HC_INTERNAL_ERROR_BAD_LFSR_FILL:
      case HC_INTERNAL_ERROR_UNEXPECTED_IN_FILE_EOF:
      case HC_INTERNAL_ERROR_BAD_TEMP_BUFFER:
      case HC_INTERNAL_ERROR_CANNOT_STAT_INPUT_FILE:
      case HC_INTERNAL_ERROR_CANNOT_SET_LFSR_SPEC:
      case HC_INTERNAL_ERROR_CANNOT_RESET_LFSR:
         status = HC_INTERNAL_ERROR;
         break;

      default:
         status = HC_INTERNAL_ERROR;
         break;
   }

   return (HcStatus) status;
}

// Fill buffer with random numbers.
bool HcEnginePrivate::randFill (void* buffer, size_t size)
{
   if (!buffer || !size)
   {
      return false;
   }

   return (0 != RAND_bytes ((unsigned char*) buffer, (int)size));
}

// What it says...
std::string HcEnginePrivate::getTempFileName (void)
{
   return boost::filesystem::unique_path().generic_string();
}

// Generate an encryption key.
int HcEnginePrivate::generateKey (int64_t file_size)
{
   uint32_t min_size = HcLfsr::getMinSize ();
   uint32_t max_size = HcLfsr::getMaxSize ();

   std::vector<uint32_t> sizes;

   int64_t s = file_size;

   // Divide up the total size into segment sizes.
   while (s && (max_size >= min_size))
   {
      if (s > max_size)
      {
         s -= max_size;
         sizes.push_back (max_size);
         continue;
      }

      max_size /= 2;
   }

   size_t min_key_count = 3;

   if (s)
   {
      --min_key_count;
   }

   // Make sure at least 3 keys are used.
   if (((file_size - s) >= (int64_t)(min_size * min_key_count)) && (sizes.size () < min_key_count))
   {
      while (sizes.size () < min_key_count)
      {
         for (auto& se : sizes)
         {
            if (se > min_size)
            {
               se /= 2;
               sizes.push_back(se);
               break;
            }
         }
      }
   }

   // Push any non power of 2 leftovers.
   if (0 != s)
   {
      sizes.push_back ((uint32_t) s);
   }

   m_key.clear ();

   HcKeyData key_data;
   memset (&key_data, 0, sizeof (key_data));

   int64_t max_progress = file_size;
   int64_t size_so_far = 0;

   // Generate the keys.
   for (auto& se : sizes)
   {
      HC_CALLBACK (HC_STATUS_KEY_CREATION_PROGRESS, (int) ((double)size_so_far * 100.0 / (double)max_progress));

      size_so_far += se;

      uint32_t fill_size = 0;
      
      if (se < getMinBlockSize ())
      {
         fill_size = getMinBlockSize () - se;
      }

      uint32_t out_size = se + fill_size;

      key_data.m_in_size = se;
      key_data.m_out_size = out_size;

      int retries = 4;

      while (--retries)
      {
         if (m_lfsr->reset (out_size, 0, -1))
         {
            break;
         }
      }

      if (!retries)
      {
         return HC_INTERNAL_ERROR_CANNOT_RESET_LFSR;
      }

      key_data.m_lfsr_specs = m_lfsr->getSpec ();

      if (!key_data.m_lfsr_specs)
      {
         return HC_INTERNAL_ERROR_BAD_LFSR_SPECS;
      }

      // Generate random AES key and vector.
      if (!randFill (&key_data.m_iv[0], sizeof (key_data.m_iv)))
      {
         return HC_INTERNAL_ERROR_CANNOT_RAND_FILL;
      }

      if (!randFill (&key_data.m_key[0], sizeof (key_data.m_key)))
      {
         return HC_INTERNAL_ERROR_CANNOT_RAND_FILL;
      }

      m_key.push_back (key_data);
   }

   // Suffle the key segments.
   if (!m_key.empty ())
   {
      uint8_t max_index = (uint8_t)(m_key.size() - 1);
      std::random_device rd;
      std::mt19937 gen(rd());

      for (uint8_t i = 1; i < max_index; ++i)
      {
         std::uniform_int_distribution<int> dist(i, max_index);

         int index = dist(gen);

         HcKeyData d = m_key[i - 1];
         m_key[i - 1] = m_key[index];
         m_key[index] = d;
      }
   }

   HC_CALLBACK (HC_STATUS_KEY_CREATION_PROGRESS, 100);

   return HC_STATUS_OK;
}

// Encrypt the next segment.  Return the status.
int HcEnginePrivate::encryptSegment (HcKeyData& key_data)
{
   if (!key_data.m_in_size || (key_data.m_out_size < key_data.m_in_size))
   {
      return HC_INTERNAL_ERROR_INVALID_INPUT_SEGMENT_SIZE;
   }

   if ((m_in_file_index >= m_in_files.size()) || !m_in_files[m_in_file_index].m_file)
   {
      return HC_ERROR_INVALID_INPUT_FILE;
   }

   if ((m_out_file_index >= m_out_files.size()) || !m_out_files[m_out_file_index].m_file)
   {
      return HC_ERROR_INVALID_OUTPUT_FILE;
   }

   if (!m_lfsr)
   {
      return HC_INTERNAL_ERROR_BAD_LFSR;
   }

   if (!m_lfsr->setSpec (key_data.m_lfsr_specs))
   {
      return HC_INTERNAL_ERROR_CANNOT_SET_LFSR_SPEC;
   }

   HC_CALLBACK (HC_STATUS_ENCRYPT_SECTION_START, 0);

   if ((size_t) key_data.m_out_size > m_buffer.size ())
   {
      return HC_INTERNAL_ERROR_BAD_TEMP_BUFFER;
   }

   uint8_t* ob = &m_buffer[0];

   // If there is a chance that a slot in the output is not going to be filled, fill the whole output buffer with random numbers.
   if (key_data.m_out_size != key_data.m_in_size)
   {
      randFill (ob, key_data.m_out_size);
   }

   uint32_t is = key_data.m_in_size;

   uint32_t chunk_size = 256;
   std::vector<uint32_t> indices;
   std::vector<uint8_t> in_buf;

   indices.resize (chunk_size);
   in_buf.resize (chunk_size);

   AES_KEY aes_key;

   AES_set_encrypt_key (key_data.m_key, 256, &aes_key);

   std::vector<uint8_t> ivec;
   ivec.resize (sizeof (key_data.m_iv));

   memcpy (&ivec[0], key_data.m_iv, ivec.size ());

   double progress = 0;
   double progress_inc = 256.0 * 100.0 / (double) is;
   double old_progress = 0;

   while (is)
   {
      uint32_t chunk = chunk_size;

      if (chunk > is)
      {
         chunk = is;
      }

      // If the last chunk is less than the minimum chunk size, pad with randoms.
      if (chunk < chunk_size)
      {
         randFill (&in_buf[chunk], chunk_size - chunk);
      }

      if (1 != fread (&in_buf[0], chunk, 1, m_in_files[m_in_file_index].m_file))
      {
         return HC_ERROR_CANNOT_READ_INPUT_FILE;
      }

      is -= chunk;

      AES_cbc_encrypt ((const unsigned char*) &in_buf[0], (unsigned char*) &in_buf[0], chunk_size, &aes_key, &ivec[0], 1);

      if (!m_lfsr->fillNext (&indices[0], chunk_size))
      {
         return HC_INTERNAL_ERROR_BAD_LFSR_FILL;
      }

      for (uint32_t i = 0; i < chunk_size - 1; ++i)
      {
         ob[indices[i]] = in_buf[i];
      }

      // If this is the last chunk in the segment, the last byte should go into index 0 since index 0 is never generated by the LFSR.
      ob[is ? indices[chunk_size - 1] : 0] = in_buf[chunk_size - 1];

      progress += progress_inc;

      if ((progress - old_progress) >= 5.0)
      {
         HC_CALLBACK (HC_STATUS_ENCRYPT_SECTION_PROGRESS, progress);
         old_progress = progress;
      }
   }

   size_t bytes_to_write = key_data.m_out_size;

   // While there are bytes to write for this segment...
   while (bytes_to_write)
   {
      if (m_out_file_index >= m_out_files.size ())
      {
         return HC_ERROR_CANNOT_WRITE_OUTPUT_FILE;
      }

      size_t chunk = bytes_to_write;

      // If the segment size is larger than the max file size...
      if (chunk > m_out_files[m_out_file_index].m_size)
      {
         chunk = m_out_files[m_out_file_index].m_size;
      }

      // Write what we can write for now.
      if (1 != fwrite (ob, chunk, 1, m_out_files[m_out_file_index].m_file))
      {
         return HC_ERROR_CANNOT_WRITE_OUTPUT_FILE;
      }

      m_out_files[m_out_file_index].m_size -= chunk;
      bytes_to_write -= chunk;
      ob += chunk;

      // If we reached the max file size...
      if (!m_out_files[m_out_file_index].m_size)
      {
         // Close this file since we are done with it.
         fclose (m_out_files[m_out_file_index].m_file);
         m_out_files[m_out_file_index].m_file = 0;

         ++m_out_file_index;
      }
   }

   HC_CALLBACK (HC_STATUS_ENCRYPT_SECTION_PROGRESS, 100);
   HC_CALLBACK (HC_STATUS_ENCRYPT_SECTION_END, 0);

   return HC_STATUS_OK;
}

// Encrypt a file.
int HcEnginePrivate::encryptFile (const char* in_file_path, uint32_t splits)
{
   if (!in_file_path || !in_file_path[0])
   {
      return HC_ERROR_BAD_INPUT_FILE_NAME;
   }

   HC_CALLBACK(HC_STATUS_ENCRYPT_START, 0);

   boost::filesystem::path in_path(in_file_path);

   std::string in_file_name = in_path.filename().generic_string();

   m_key_file.clear ();

   std::string key_file_name = in_file_name + ".hckey";

   if (boost::filesystem::exists(key_file_name))
   {
      return HC_ERROR_KEY_FILE_ALREADY_EXISTS;
   }

   m_key_file.m_file_name = key_file_name;
   m_key_file.m_temp_file_name = getTempFileName () + "-hctemp";

   m_out_files.clear();
   m_out_file_index = 0;

   if (splits)
   {
      char temp[64];

      FileSpec fs;

      fs.m_file = 0;
      fs.m_size = 0;

	  // If the output file is to be split, generate the output file names.
      for (size_t i = 0; i < splits; ++i)
      {
         fs.m_file_name = in_file_name;
         sprintf (temp, ".%02d.hc", i + 1);
         fs.m_file_name += temp;

         if (boost::filesystem::exists(fs.m_file_name))
         {
            m_out_files.clear ();
            return HC_ERROR_OUTPUT_FILE_ALREADY_EXISTS;
         }

         m_out_files.push_back (fs);
      }
   }
   else
   {
      FileSpec fs;

      fs.m_file = 0;
      fs.m_size = 0;

      fs.m_file_name = in_file_name;
      fs.m_file_name += ".hc";

      if (boost::filesystem::exists(fs.m_file_name))
      {
         m_out_files.clear ();
         return HC_ERROR_OUTPUT_FILE_ALREADY_EXISTS;
      }

      m_out_files.push_back (fs);
   }

   for (auto& e : m_out_files)
   {
      e.m_temp_file_name = getTempFileName () + "-hctemp";
   }

   if (!boost::filesystem::exists (in_file_path))
   {
      return HC_ERROR_CANNOT_OPEN_INPUT_FILE;
   }

   size_t file_size = 0;
   
   try
   {
	   file_size = boost::filesystem::file_size(in_file_path);

	   if (!file_size)
	   {
		   throw;
	   }
   }
   catch (...)
   {
	   return HC_ERROR_CANNOT_OPEN_INPUT_FILE;
   }

   FileSpec in_file_spec;

   in_file_spec.m_file = fopen (in_file_path, "rb");
   
   if (!in_file_spec.m_file)
   {
      return HC_ERROR_CANNOT_OPEN_INPUT_FILE;
   }

   m_in_files.clear();
   m_in_file_index = 0;

   in_file_spec.m_size = file_size;

   m_in_files.push_back (in_file_spec);

   HC_CALLBACK (HC_STATUS_KEY_CREATION_START, 0);

   // Create the LFSR.
   m_lfsr = new HcLfsr (0);

   int status = generateKey (file_size);

   if (HC_STATUS_OK != status)
   {
      return status;
   }

   HC_CALLBACK (HC_STATUS_KEY_CREATION_END, 0);

   size_t total_out_size = 0;
   size_t max_segment_size = 0;

   // Calculate the expected output file size.
   for (auto& ke : m_key)
   {
      if (max_segment_size < ke.m_out_size)
      {
         max_segment_size = ke.m_out_size;
      }
      total_out_size += ke.m_out_size;
   }

   try
   {
      m_buffer.resize (max_segment_size);
   }
   catch (...)
   {
   }

   if (m_buffer.size () != max_segment_size)
   {
      return HC_ERROR_BLOCK_SIZE_TOO_BIG;
   }

   if (splits)
   {
	   // The output file size must be at least the size of the smallest LFSR sequence.
      if (total_out_size < HcLfsr::getMinSize())
      {
         return HC_ERROR_BAD_KEY;
      }

	  uintmax_t chunk_size = total_out_size / splits;

	  // Make sure the splits happen at a 256-byte boundary.
	  if (chunk_size & 0xFF)
	  {
		  chunk_size = (chunk_size & ~0xFF) + 0x100;
	  }

      size_t temp = total_out_size;

      // Set the size of each split.
	  for (size_t i = 0; i < m_out_files.size (); ++i)
      {
         m_out_files[i].m_size = (temp > chunk_size) ? chunk_size : temp;
         temp -= m_out_files[i].m_size;
      }
   }
   else
   {
      m_out_files[0].m_size = total_out_size;
   }

   // Open all the output files for writing.
   for (auto& e : m_out_files)
   {
      e.m_file = fopen (e.m_temp_file_name.c_str (), "wb");

      if (!e.m_file)
      {
         return HC_ERROR_CANNOT_CREATE_OUTPUT_FILE;
      }
   }

   size_t progress = 0;

   HC_CALLBACK (HC_STATUS_ENCRYPT_PROGRESS, 0);

   // Encrypt all the segments
   for (auto& ke : m_key)
   {
      HcKeyData kd = ke;

      int status = encryptSegment (kd);

      if (HC_STATUS_OK != status)
      {
         return status;
      }

      progress += ke.m_out_size;

      HC_CALLBACK (HC_STATUS_ENCRYPT_PROGRESS, ((double)progress * 100.0 / (double)total_out_size));
   }

   HC_CALLBACK (HC_STATUS_ENCRYPT_PROGRESS, 100);

   if (m_key.empty ())
   {
      return HC_ERROR_BAD_KEY;
   }

   // Create the key file.
   int result = keyToXmlFile (m_key_file.m_temp_file_name.c_str ());

   if (HC_STATUS_OK != result)
   {
      return result;
   }

   // After the temp output files and temp key file have been written succuessfuly, rename them to the actual file names.
   // This is used so that no partial files and left over in case an error happens in the middle of the operation.
   if (rename (m_key_file.m_temp_file_name.c_str (), m_key_file.m_file_name.c_str ()) < 0)
   {
      return HC_ERROR_CANNOT_WRITE_KEY_FILE;
   }

   for (auto& e : m_out_files)
   {
      if (rename (e.m_temp_file_name.c_str (), e.m_file_name.c_str ()) < 0)
      {
         return HC_ERROR_CANNOT_WRITE_OUTPUT_FILE;
      }
   }

   for (auto& e : m_out_files)
   {
      e.clear ();
   }

   m_key_file.clear ();

   cleanUp ();

   HC_CALLBACK (HC_STATUS_ENCRYPT_END, 0);

   return HC_STATUS_OK;
}

// Decrypt the next segment.  Return the status.
int HcEnginePrivate::decryptSegment (HcKeyData& key_data)
{
   if (!m_lfsr->setSpec (key_data.m_lfsr_specs))
   {
      return HC_INTERNAL_ERROR_CANNOT_SET_LFSR_SPEC;
   }

   if (key_data.m_in_size > key_data.m_out_size)
   {
      return HC_ERROR_BAD_KEY;
   }

   if (!key_data.m_in_size)
   {
	   return HC_ERROR_BAD_KEY;
   }

   size_t bytes_to_read = key_data.m_out_size;
   size_t bytes_read = 0;

   while (bytes_to_read)
   {
      if (m_in_file_index >= m_in_files.size ())
      {
         return HC_ERROR_CANNOT_READ_INPUT_FILE;
      }

      size_t res = fread (&m_buffer[bytes_read], 1, bytes_to_read, m_in_files [m_in_file_index].m_file);

      if (res != bytes_to_read)
      {
         ++m_in_file_index;
      }

      bytes_to_read -= res;
      bytes_read += res;
   };

   uint8_t* ib = &m_buffer[0];
   uint32_t is = key_data.m_in_size;

   uint32_t chunk_size = 256;
   std::vector<uint32_t> indices;
   std::vector<uint8_t> out_buf;

   indices.resize (chunk_size);
   out_buf.resize (chunk_size);

   AES_KEY aes_key;

   AES_set_decrypt_key (key_data.m_key, 256, &aes_key);

   std::vector<uint8_t> ivec;
   ivec.resize (sizeof (key_data.m_iv));

   memcpy (&ivec[0], key_data.m_iv, ivec.size ());

   HC_CALLBACK(HC_STATUS_DECRYPT_SECTION_START, 0);

   double progress = 0;
   double progress_inc = 256.0 * 100.0 / (double)is;
   double old_progress = 0;

   while (is)
   {
      uint32_t chunk = chunk_size;

      if (chunk > is)
      {
         chunk = is;
      }

      if (!m_lfsr->fillNext (&indices[0], chunk_size))
      {
         return HC_INTERNAL_ERROR_BAD_LFSR_FILL;
      }

      for (uint32_t i = 0; i < (chunk_size - 1); ++i)
      {
         out_buf[i] = ib [indices [i]];
      }

      out_buf[chunk_size - 1] = ib [(is != chunk) ? indices [chunk_size - 1] : 0];

      AES_cbc_encrypt ((const unsigned char*) &out_buf[0], (unsigned char*) &out_buf[0], chunk_size, &aes_key, &ivec[0], 0);

      if (1 != fwrite (&out_buf[0], chunk, 1, m_out_files[0].m_file))
      {
         return HC_ERROR_CANNOT_WRITE_OUTPUT_FILE;
      }

      is -= chunk;

	  progress += progress_inc;

	  if ((progress - old_progress) >= 5.0)
	  {
		  HC_CALLBACK(HC_STATUS_DECRYPT_SECTION_PROGRESS, progress);
		  old_progress = progress;
	  }
   }

   HC_CALLBACK(HC_STATUS_DECRYPT_SECTION_PROGRESS, 100);
   HC_CALLBACK(HC_STATUS_DECRYPT_SECTION_END, 0);

   return HC_STATUS_OK;
}

// Decrypt a file.
int HcEnginePrivate::decryptFile (const char* key_file_path, unsigned long joins)
{
   if (!key_file_path || !key_file_path[0])
   {
      return HC_ERROR_BAD_INPUT_FILE_NAME;
   }

   FileSpec ofs;

   ofs.m_file_name = boost::filesystem::basename (boost::filesystem::path (key_file_path));

   // Make sure the output file does not exist in the current dir.
   if (boost::filesystem::exists(ofs.m_file_name))
   {
      return HC_ERROR_OUTPUT_FILE_ALREADY_EXISTS;
   }

   ofs.m_temp_file_name = getTempFileName () + "-hctemp";

   uintmax_t total_file_size = 0;

   HC_CALLBACK(HC_STATUS_DECRYPT_START, 0);

   if (!joins)
   {
      std::string fn = ofs.m_file_name + ".hc";

      try
      {
         total_file_size = boost::filesystem::file_size(fn);

		 if (!total_file_size)
		 {
			 throw;
		 }
      }
      catch (...)
      {
         return HC_ERROR_CANNOT_OPEN_INPUT_FILE;
      }

      FileSpec fs;

      fs.m_file = fopen (fn.c_str(), "rb");

      if (!fs.m_file)
      {
         return HC_ERROR_CANNOT_OPEN_INPUT_FILE;
      }

      m_in_files.push_back(fs);
   }
   else
   {
      for (uint32_t i = 0; i < joins; ++i)
      {
         char temp[64];

         sprintf (temp, ".%02d.hc", i + 1);

         FileSpec fs;

         fs.m_file_name = ofs.m_file_name + temp;

         try
         {
            fs.m_size = boost::filesystem::file_size(fs.m_file_name);

			if (!fs.m_size)
			{
				throw;
			}
            total_file_size += fs.m_size;
         }
         catch (...)
         {
            return HC_ERROR_CANNOT_OPEN_INPUT_FILE;
         }

         fs.m_file = fopen (fs.m_file_name.c_str (), "rb");

         if (!fs.m_file)
         {
            return HC_ERROR_CANNOT_OPEN_INPUT_FILE;
         }

         m_in_files.push_back (fs);
      }
   }

   uint64_t out_total_size = 0;
   uint64_t in_total_size = 0;

   for (auto& ke : m_key)
   {
      out_total_size += ke.m_out_size;
      in_total_size += ke.m_in_size;
   }

   if (out_total_size != total_file_size)
   {
      return HC_ERROR_INVALID_INPUT_FILE;
   }

   ofs.m_size = in_total_size;

   ofs.m_file = fopen (ofs.m_temp_file_name.c_str (), "wb");

   if (!ofs.m_file)
   {
      return HC_ERROR_CANNOT_CREATE_OUTPUT_FILE;
   }

   m_out_files.push_back (ofs);

   size_t progress = 0;

   HC_CALLBACK(HC_STATUS_DECRYPT_PROGRESS, 0);

   for (auto& ke : m_key)
   {
      int status = decryptSegment (ke);

      if (HC_STATUS_OK != status)
      {
         return status;
      }

		progress += ke.m_in_size;

		HC_CALLBACK(HC_STATUS_DECRYPT_PROGRESS, ((double)progress * 100.0 / (double)in_total_size));
   }

   HC_CALLBACK(HC_STATUS_DECRYPT_PROGRESS, 100);

   fclose (m_out_files[0].m_file);
   m_out_files[0].m_file = 0;

   if (rename (m_out_files[0].m_temp_file_name.c_str(), m_out_files[0].m_file_name.c_str()) < 0)
   {
      return HC_ERROR_CANNOT_WRITE_OUTPUT_FILE;
   }

   m_out_files[0].m_file_name.clear ();
   m_out_files[0].m_temp_file_name.clear ();

   cleanUp ();

   HC_CALLBACK (HC_STATUS_DECRYPT_END, 0);

   return HC_STATUS_OK;
}

#define XML_HC_ROOT           "HyperCryptKey"
#define XML_HC_VERSION        "version"
#define XML_HC_SEGMENTS       "Segments"
#define XML_HC_SEGMENT        "Segment"
#define XML_HC_IN_SIZE        "in_size"
#define XML_HC_OUT_SIZE       "out_size"
#define XML_HC_LFSR           "lfsr"
#define XML_HC_CRYPTO         "Crypto"
#define XML_HC_CRYPTO_SCHEME  "scheme"
#define XML_HC_CRYPTO_KEY     "key"
#define XML_HC_CRYPTO_IV      "iv"

int HcEnginePrivate::keyToXmlFile (const char* key_file_path)
{
   if (!key_file_path || !key_file_path[0])
   {
      return HC_ERROR_INVALID_KEY_FILE;
   }

   char temp[1024];

   std::string xml_string;

   xml_string = "<" XML_HC_ROOT ">";
   xml_string += "<" XML_HC_VERSION ">";

   sprintf (temp, "%08X", KEY_VERSION);

   xml_string += temp;
   xml_string += "</" XML_HC_VERSION ">";
   xml_string += "<" XML_HC_SEGMENTS ">";

   for (auto& ke : m_key)
   {
      xml_string += "<" XML_HC_SEGMENT ">";
      sprintf (temp, "<" XML_HC_IN_SIZE ">%u</" XML_HC_IN_SIZE ">", ke.m_in_size);
      xml_string += temp;
      sprintf (temp, "<" XML_HC_OUT_SIZE ">%u</" XML_HC_OUT_SIZE ">", ke.m_out_size);
      xml_string += temp;
      sprintf (temp, "<" XML_HC_LFSR ">%llu</" XML_HC_LFSR ">", ke.m_lfsr_specs);
      xml_string += temp;
      xml_string += "<" XML_HC_CRYPTO ">";
      xml_string += "<" XML_HC_CRYPTO_SCHEME ">" CRYPTO_SCHEME "</" XML_HC_CRYPTO_SCHEME ">";
      xml_string += "<" XML_HC_CRYPTO_IV ">";
      hexToString (ke.m_iv, sizeof (ke.m_iv), xml_string);
      xml_string += "</" XML_HC_CRYPTO_IV ">";
      xml_string += "<" XML_HC_CRYPTO_KEY ">";
      hexToString (ke.m_key, sizeof (ke.m_key), xml_string);
      xml_string += "</" XML_HC_CRYPTO_KEY ">";
      xml_string += "</" XML_HC_CRYPTO ">";
      xml_string += "</" XML_HC_SEGMENT ">";
   }

   xml_string += "</" XML_HC_SEGMENTS ">";
   xml_string += "</" XML_HC_ROOT ">";

   FILE* f = fopen (key_file_path, "w");

   if (!f)
   {
      return HC_ERROR_CANNOT_CREATE_KEY_FILE;
   }

   if (1 != fwrite (xml_string.c_str (), xml_string.size (), 1, f))
   {
      fclose (f);
      return HC_ERROR_CANNOT_WRITE_KEY_FILE;
   }

   fclose (f);

   return HC_STATUS_OK;
}

int HcEnginePrivate::xmlFileToKey (const char* key_file_path)
{
   if (!key_file_path || !*key_file_path)
   {
      return HC_ERROR_BAD_KEY_FILE_NAME;
   }

   if (!boost::filesystem::exists (key_file_path))
   {
      return HC_ERROR_CANNOT_OPEN_KEY_FILE;
   }

   try
   {
      m_key.clear ();

      boost::property_tree::ptree pt;
      boost::property_tree::xml_parser::read_xml (key_file_path, pt);

      std::string version = pt.get<std::string> (XML_HC_ROOT "." XML_HC_VERSION);

      auto segments = pt.get_child (XML_HC_ROOT "." XML_HC_SEGMENTS);

      HcKeyData kd;

      for (auto& s : segments)
      {
         std::string crypto_scheme;
         std::string crypto_iv_str;
         std::string crypto_key_str;

         if (s.first.compare (XML_HC_SEGMENT))
         {
            continue;
         }

         kd.m_in_size      = s.second.get<uint32_t> (XML_HC_IN_SIZE);
         kd.m_out_size     = s.second.get<uint32_t> (XML_HC_OUT_SIZE);
         kd.m_lfsr_specs   = s.second.get<uint64_t> (XML_HC_LFSR);

         auto& c = s.second.get_child (XML_HC_CRYPTO);

         crypto_scheme = c.get<std::string> (XML_HC_CRYPTO_SCHEME);
         crypto_iv_str = c.get<std::string> (XML_HC_CRYPTO_IV);
         crypto_key_str = c.get<std::string> (XML_HC_CRYPTO_KEY);

         if (!stringToHex (&kd.m_iv, sizeof (kd.m_iv), crypto_iv_str))
         {
            throw;
         }

         if (!stringToHex (&kd.m_key, sizeof (kd.m_key), crypto_key_str))
         {
            throw;
         }

         m_key.push_back (kd);
      }
   }
   catch (...)
   {
      m_key.clear ();
      return HC_ERROR_BAD_KEY;
   }

   return HC_STATUS_OK;
}

void HcEnginePrivate::hexToString (const void* buffer, int count, std::string& str)
{
   unsigned char* b = (unsigned char*)buffer;

   if (!b || !count)
   {
      return;
   }

   while (count--)
   {
      char t[64];
      sprintf (t, "%02X", *b);
      str += t;
      ++b;
   }
}

bool HcEnginePrivate::stringToHex (void* buffer, int count, const std::string& str)
{
   if (!buffer || !count || (str.length () != (size_t)(count * 2)))
   {
      return false;
   }

   unsigned char* b = (unsigned char*)buffer;
   const char* s = str.c_str ();

   while (count--)
   {
      int n = 0;
      *b = 0;

      for (int i = 0; i < 2; ++i)
      {
         *b <<= 4;

         if ((*s >= '0') && (*s <= '9'))
         {
            n = *s - '0';
         }
         else if ((*s >= 'A') && (*s <= 'F'))
         {
            n = *s - 'A' + 10;
         }
         else
         {
            return false;
         }

         *b |= n;
         ++s;
      }

      ++b;
   }

   return true;
}

//------------------------------------------
HcEngine* HcEngine::create (void)
{
   return new HcEnginePrivate;
}

void HcEngine::destroy (HcEngine* engine)
{
   if (engine)
   {
      delete (static_cast<HcEnginePrivate*>(engine));
   }
}
