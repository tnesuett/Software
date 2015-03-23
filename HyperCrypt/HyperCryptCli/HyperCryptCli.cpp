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

#include <stdio.h>
#include <stdlib.h>

#include <boost/filesystem.hpp>
#include <boost/filesystem/convenience.hpp>
#include <string>

#include "HcEngine.hpp"

#define VERSION "1.0"

static void display_status (HcStatus status)
{
   #define CASE(x,s) case x: printf (s); break

   switch (status)
   {
      CASE (HC_ERROR_INVALID_INPUT_FILE,        "Error: Invalid input file!\n");
      CASE (HC_ERROR_CANNOT_OPEN_INPUT_FILE,    "Error: Cannot open input file!\n");
      CASE (HC_ERROR_CANNOT_READ_INPUT_FILE,    "Error: Cannot read input file!\n");
      CASE (HC_ERROR_BAD_INPUT_FILE_NAME,       "Error: Bad input file name!\n");
      CASE (HC_ERROR_INVALID_OUTPUT_FILE,       "Error: Invalid output file!\n");
      CASE (HC_ERROR_CANNOT_CREATE_OUTPUT_FILE, "Error: Cannot create output file!\n");
      CASE (HC_ERROR_CANNOT_WRITE_OUTPUT_FILE,  "Error: Cannot write output file!\n");
      CASE (HC_ERROR_BAD_OUTPUT_FILE_NAME,      "Error: Bad output file name!\n");
      CASE (HC_ERROR_INVALID_KEY_FILE,          "Error: Invalid key file!\n");
      CASE (HC_ERROR_CANNOT_OPEN_KEY_FILE,      "Error: Cannot open key file!\n");
      CASE (HC_ERROR_CANNOT_CREATE_KEY_FILE,    "Error: Cannot create key file!\n");
      CASE (HC_ERROR_CANNOT_READ_KEY_FILE,      "Error: Cannot read key file!\n");
      CASE (HC_ERROR_CANNOT_WRITE_KEY_FILE,     "Error: Cannot write key file!\n");
      CASE (HC_ERROR_INVALID_KEY,               "Error: Invalid key!\n");
      CASE (HC_ERROR_CANNOT_CREATE_KEY,         "Error: Cannot create key!\n");
      CASE (HC_ERROR_BAD_KEY,                   "Error: Bad key!\n");
      CASE (HC_ERROR_BAD_KEY_FILE_NAME,         "Error: Bad key file name!\n");
      CASE (HC_ERROR_CANNOT_ENCRYPT_SECTION,    "Error: Cannot encrypt file section!\n");
      CASE (HC_ERROR_CANNOT_ENCRYPT_FILE,       "Error: Cannot encrypt file!\n");
      CASE (HC_ERROR_CANNOT_DECRYPT_SECTION,    "Error: Cannot decrypt file section!\n");
      CASE (HC_ERROR_CANNOT_DECRYPT_FILE,       "Error: Cannot decrypt file!\n");
      CASE (HC_ERROR_CALLBACK_EXCEPTION,        "Error: Bad callback!\n");
      CASE (HC_ERROR_BLOCK_SIZE_TOO_BIG,        "Error: Block size too big!\n");
      CASE (HC_ERROR_OUTPUT_FILE_ALREADY_EXISTS,"Error: Output file already exists!\n");
      CASE (HC_ERROR_KEY_FILE_ALREADY_EXISTS,   "Error: Key file already exists!\n");
      CASE (HC_INTERNAL_ERROR,                  "Error: Internal error!\n");

      CASE (HC_STATUS_OK,                    "Success!\n");

      default:
         if (status < 0)
         {
            display_status (HC_INTERNAL_ERROR);
            break;
         }

         break;
   }
}

static void show_encrypt_syntax (void)
{
   printf ("\nVersion: " VERSION "\n\n");
   printf ("Encrypt Syntax: hypercrypt -e <file>\n");
   printf ("   example: hypercrypt -e my_file.txt\n");
   printf ("    output: my_file.txt.hckey my_file.txt.hc\n\n");

   printf ("Encrypt and Split Syntax: hypercrypt -e -s <splits> <file>\n");
   printf ("   example: hypercrypt -e -s 3 my_file.txt\n");
   printf ("    output: my_file.txt.hckey my_file.txt.hc my_file.txt.01.hc my_file.txt.02.hc my_file.txt.03.hc\n\n");
}

static void show_decrypt_syntax (void)
{
   printf ("Decrypt Syntax: hypercrypt -d <key file>\n");
   printf ("   example: hypercrypt -d my_file.txt.hckey\n");
   printf ("   file my_file.txt.hc must be present\n\n");

   printf ("Decrypt and Join: hypercrypt -d -j <joins> <key file>\n");
   printf ("   example: hypercrypt -d my_file.txt.hckey\n");
   printf ("   files my_file.txt.01.hc, my_file.txt.02.hc, and my_file.txt.03.hc must be present\n\n");
}

static void show_syntax (void)
{
   show_encrypt_syntax ();
   show_decrypt_syntax ();
}

static void hc_callback (void*, HcStatus status, int status_data)
{
   if (status <= 0)
   {
      display_status (status);
      return;
   }

   switch (status)
   {
      case HC_STATUS_KEY_CREATION_START:        printf ("Creating key: \r");                    break;
      case HC_STATUS_KEY_CREATION_PROGRESS:     printf ("Creating key: %3d%%\r", status_data);  break;
      case HC_STATUS_KEY_CREATION_END:          printf ("Creating key: Done.\n");               break;
      case HC_STATUS_ENCRYPT_START:             printf ("Encrypting:\n");                       break;
      case HC_STATUS_ENCRYPT_SECTION_PROGRESS:  printf ("   Section: %3d%%\r", status_data);    break;
      case HC_STATUS_ENCRYPT_SECTION_END:       printf ("   Section: Done.\n");                 break;
      case HC_STATUS_ENCRYPT_PROGRESS:          printf ("Encrypting: %3d%%\n", status_data);    break;
      case HC_STATUS_ENCRYPT_END:               printf ("Encrypting: Done.\n");                 break;
	  case HC_STATUS_DECRYPT_START:              printf("Decrypting:\n");                       break;
	  case HC_STATUS_DECRYPT_SECTION_PROGRESS:   printf("   Section: %3d%%\r", status_data);    break;
	  case HC_STATUS_DECRYPT_SECTION_END:        printf("   Section: Done.\n");                 break;
	  case HC_STATUS_DECRYPT_PROGRESS:           printf("Decrypting: %3d%%\n", status_data);    break;
	  case HC_STATUS_DECRYPT_END:                printf("Decrypting: Done.\n");                 break;

      default:
         break;
   }
}

// TODO:  Check the integrity of the input params.  Probably use boost to handle the options passed in.
// TODO:  Check key version.
int main (int argc, char* argv[])
{
   if (argc < 3)
   {
      show_syntax ();
      return -1;
   }

   HcEngine* engine = HcEngine::create ();

   if (!engine)
   {
      printf ("Cannot create encryption engine!\n");
      return -1;
   }

   int result = -1;
   int arg_index = 1;

   while (engine)
   {
      std::string opt = argv[arg_index++];

      if (!opt.compare ("-e"))
      {
         int splits = 0;
         opt = argv[arg_index];

         if (!opt.compare ("-s"))
         {
            if (argc != 5)
            {
               show_encrypt_syntax ();
               break;
            }

            ++arg_index;

            splits = atoi (argv[arg_index++]);

            if ((splits < 2) || (splits > 16))
            {
               printf ("Splits should be between 2 and 16.\n");
               break;
            }
         }

         std::string in_file_name = argv[arg_index];

         HcStatus status = engine->encryptFile (splits, in_file_name.c_str (), hc_callback, 0);

         display_status (status);

         result = (HC_STATUS_OK == status) ? 0 : -1;
         break;
      }

      if (!opt.compare ("-d"))
      {
         int joins = 0;
         opt = argv[arg_index];

         if (!opt.compare ("-j"))
         {
            if (argc != 5)
            {
               show_decrypt_syntax ();
               break;
            }

            ++arg_index;

            joins = atoi (argv[arg_index++]);

            if ((joins < 2) || (joins > 16))
            {
               printf ("Joins should be between 2 and 16.\n");
               break;
            }
         }

         std::string key_file_name = argv[arg_index];

         HcStatus status = engine->decryptFile (joins, key_file_name.c_str (), hc_callback, 0);

         display_status (status);

         result = (HC_STATUS_OK == status) ? 0 : -1;
      }

	  break;
   };

   HcEngine::destroy (engine);

   return result;
}

