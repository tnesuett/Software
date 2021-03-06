HyperCrypt Version 1.0

HyperCrypt builds on the encryption algorithms provided by the openssl 
library to help further secure large files. This current version relies on 
AES-256, but any other symmetric encryption scheme can work.

Symmetric encryption schemes like AES and DES work on small blocks (16 bytes 
for example) at a time. If someone is trying to figure out the key, they only 
need to decrypt that block and try to see if it makes sense as a clear text. 
This task is usually helped by the different file formats that have a sentinel 
at the beginning of the file; e.g. PDF.

HyperCrypt does a two-pass encryption. The first pass is to encrypt the file 
using AES - this is done one segment at a time; each segment is between 32K and 
256M depending on the file size. Then, for every segment, it shuffles the bytes 
within that segment. The shuffle is a pseudo random function that is 
reversible. During the decryption phase, the reverse is done to first 
un-shuffle the bytes, then decrypt them using AES. In short, HyperCrypt 
disrupts any cohesion that may exist within an encrypted block as generated by 
AES.

The obstacle to someone trying to recover the key is that they first have to 
un-shuffle the file before trying to guess a decryption key.
Unlike other encryption methods, each encrypted file generates a matched key 
file. That key file can only decrypt the encrypted file associated with it. In 
the upcoming releases, a feature to create a shared key will be added. Both 
methods have advantages and disadvantages, with the current one being more 
secure at the expense of multiple key files for different encrypted files.

Usage:
======

The simplest form to encrypt a file is:

hypercrypt -e myfile.txt

This will generate myfile.txt.hc (the encrypted file) and myfile.txt.hckey (the 
encryption key)

To decrypt the file, make sure myfile.txt.hc and myfile.txt.hckey exist in the 
current directory and run:

hypercrypt -d myfile.txt.hckey

This will generate the decrypted myfile.txt file.
If the file to encrypt is too large and splitting makes more sense, the -s 
option can be used.

hypercrypt -e -s 3 myfile.txt

This will generate myfile.txt.01.hc, myfile.txt.02.hc, and myfile.txt.03.hc

To decrypt, make sure all the .hc files are in the current directory and run:

hypercrypt -d -j 3 myfile.txt.hckey

Build:
======

HyperCrypt requires boost (1.57.0 was used) and openssl (1.0.2 was used)

Windows 7:
----------

If you are using the provided project files, they are for VS2013 Community version.
Make sure c:\boost\1.57.0 is where boost is installed and c:\openssl is where openssl is installed.
If you have other boost/openssl version, you will need to change the include and library paths.

Linux:
------

Make sure opensll and boost are installed and the path is configured correctly.
To build, run:

make

this will generate the file hypercrypt
