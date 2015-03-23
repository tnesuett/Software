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

#ifndef __HCENGINE_HPP__
#define __HCENGINE_HPP__

enum HcStatus
{
   HC_ERROR_INVALID_INPUT_FILE = -1000,
   HC_ERROR_CANNOT_OPEN_INPUT_FILE,
   HC_ERROR_CANNOT_READ_INPUT_FILE,
   HC_ERROR_BAD_INPUT_FILE_NAME,
   HC_ERROR_INVALID_OUTPUT_FILE,
   HC_ERROR_CANNOT_CREATE_OUTPUT_FILE,
   HC_ERROR_CANNOT_WRITE_OUTPUT_FILE,
   HC_ERROR_BAD_OUTPUT_FILE_NAME,
   HC_ERROR_INVALID_KEY_FILE,
   HC_ERROR_CANNOT_OPEN_KEY_FILE,
   HC_ERROR_CANNOT_CREATE_KEY_FILE,
   HC_ERROR_CANNOT_READ_KEY_FILE,
   HC_ERROR_CANNOT_WRITE_KEY_FILE,
   HC_ERROR_INVALID_KEY,
   HC_ERROR_CANNOT_CREATE_KEY,
   HC_ERROR_BAD_KEY,
   HC_ERROR_BAD_KEY_FILE_NAME,
   HC_ERROR_CANNOT_ENCRYPT_SECTION,
   HC_ERROR_CANNOT_ENCRYPT_FILE,
   HC_ERROR_CANNOT_DECRYPT_SECTION,
   HC_ERROR_CANNOT_DECRYPT_FILE,
   HC_ERROR_CALLBACK_EXCEPTION,
   HC_ERROR_BLOCK_SIZE_TOO_BIG,
   HC_ERROR_OUTPUT_FILE_ALREADY_EXISTS,
   HC_ERROR_KEY_FILE_ALREADY_EXISTS,
   HC_INTERNAL_ERROR,

   HC_STATUS_OK = 0,
   HC_STATUS_KEY_CREATION_START,
   HC_STATUS_KEY_CREATION_PROGRESS,
   HC_STATUS_KEY_CREATION_END,
   HC_STATUS_ENCRYPT_START,
   HC_STATUS_ENCRYPT_PROGRESS,
   HC_STATUS_ENCRYPT_END,
   HC_STATUS_ENCRYPT_SECTION_START,
   HC_STATUS_ENCRYPT_SECTION_PROGRESS,
   HC_STATUS_ENCRYPT_SECTION_END,
   HC_STATUS_DECRYPT_START,
   HC_STATUS_DECRYPT_PROGRESS,
   HC_STATUS_DECRYPT_END,
   HC_STATUS_DECRYPT_SECTION_START,
   HC_STATUS_DECRYPT_SECTION_PROGRESS,
   HC_STATUS_DECRYPT_SECTION_END,
   HC_STATUS_ANALYSE_FILE_START,
   HC_STATUS_ANALYSE_FILE_END,
   HC_STATUS_DONE,
};

typedef void (*HcEngineCallback)(void* context, HcStatus status, int status_data);

class HcEngine
{
   public:
      static HcEngine* create (void);
      static void destroy (HcEngine* engine);

      virtual unsigned long getMinBlockSize (void) = 0;
      virtual unsigned long getMaxBlockSize (void) = 0;

      virtual HcStatus encryptFile (unsigned long splits, const char* file_path, HcEngineCallback callback, void* context) = 0;
      virtual HcStatus decryptFile (unsigned long joins, const char* key_file_path, HcEngineCallback callback, void* context) = 0;

   protected:
      virtual ~HcEngine (void) {}
};

#endif
