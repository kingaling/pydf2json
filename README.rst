PyDF2JSON
=========

This code was written so that I could do more detailed analysis of PDF documents, on the fly and incorporate it into a security stack. "On the fly" is key. PyDF2JSON simply creates a json structure out of PDF documents. It breaks a PDF document down into all its individual parts, and retains those parts for analysis. Once this is done, a more detailed analysis should be possible.

Installation
------------

Clone the repo and use it. Optionally, run python setup.py build/install to make the pydf2json module importable by all the things. You can also use pip install [--upgrade] pydf2json

Usage
-----

::

   > pydf.py
     usage: pydf.py [-h] [-d LOCATION] [-s MAX_SIZE] [-p PASSWORD] [--no_summary]
                    [--show_json] [--show_text] [--show_ttf] [--show_bitmap]
                    [--show_pics] [--show_embedded_files] [--show_arbitrary]
                    [--show_all]
                    pdf
  
   > pydf.py secure_dropbox.pdf -p 29576AE2
     Summary of PDF attributes:
     --------------------------

     Encrypted:                    True
     Key:                          030359FF89FC8A8EB764E97AD2ED7091
     Key Length:                   128
     Algo:                         RC4

     Additional Actions:           0
     AcroForms:                    0
     Embedded Files:               0
     JS:                           0
     Launch:                       0
     Object Streams:               8
     OpenActions:                  0
     Pages:                        1

     URIs in document:
             http://<redacted>.xyz/sign-up/
             http://<redacted>.xyz/signup/

     Document Hashes:
             SHA1       8733CC6196C7F26F027078E6A51B822462DA2CA3
             SHA256     9D64D1EBA74F7078F5F524CCB4F79F3D41F1B7A631DE81D9FF2870FF5E4D2DFD
             MD5        0F49F102421C286E50CD40EBDDB105AF

pydf.py calls the pydf2json module to convert the PDF into a json-style dict and then accesses the structure to create the summary you see above.

Error Reporting
---------------

I am versed in the concept of OPSEC. If you have a PDF that this fails on / causes crash, Please send me the PDF in question if possible. No document sent to me will be shared with anyone at anytime and will be destroyed when I'm done testing with it. Archive it with a utility like 7Zip and encrypt it with the following password: ``fr74ed83e.dj#ifkk``

Send it to ``kingaling@meatchicken.net``
The password is simply to keep PDF from being scanned by AV. :)

My Reasons
----------

This code was inspired by my desire to have a pdf analysis module for the LaikaBOSS framework.
See: `LaikaBOSS <https://github.com/lmco/laikaboss>`_ developed by Lockheed Martin.

Recent Activity
---------------
20180526
    - Rewrote code that extracts EmbedddFiles and JavaScript summary info.

History
-------
20180515
    - Decodes some page text
        - Introduced new stream type: pdf_mcid
        - Works on most (hopefully), but not all.
    - Decrypt documents that require a password
        - Added command line switch to accomodate this: -p
    - Added new freebase function that can convert a number of any base to any other base
        - Used this to rework the ascii85 decoder which was flawed.
    - Various other cosmetic / logic issues

20180312 - New pydf.py argument
    - Added -s command line switch to specify the max size of the PDF to process
       - pydf2json code has a 2MB hardcoded limit which can be changed when module is called.
       - For inline analysis this will limit the analysis done.
       - It's rare (where I work) to see a malicious PDF that exceeds 2MB, even 1MB.
           - I may implement another analysis technique for files that exceed the limit
           - Also, LaikaBOSS can use ClamAV and possibly other scan engines. I'll have to look into that.

20180228 - Page tracking
    - Added info to the summary that notes what page a hyperlink occurred on
        - Not a page numbers; a custom identifier to aide in deciding if a page has been modified
        - This will be needed for the LaikaBOSS module for that smarter detection I mentioned in the wiki.

20180131 - Additional processing capabilities added.
    - Added processing of Additional Actions (/AA).
    - Arbitrary data found outside of any known PDF object is now subject to analysis

20180103 - Added decryption capabilities
    - Standard Security Handler Version 1, 2 & 4; Revision 2, 3, & 4
        - Tested code on CFM methods V2 and AESV2 (RC4 and AES respectively)
    - Code will exit upon discovering encryption if pycrypto modules have not been loaded
        - So please do 'pip install pycrypto'

20171128 - Major rewrite of some core functionality
	- pydf2json now returns a tuple
		- The JSON struct of the PDF
		- A summary of data that can be used to create meaningful output to end user.
		- An object map for easy access to various objects within the JSON struct.

To Do
-----

1. Decryption
    - [ ] Need to read the newest PDF standard and add the V5 encryption/decryption algorithms.