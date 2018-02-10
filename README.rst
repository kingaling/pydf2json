PyDF2JSON
=========

This code was written so that I could do more detailed analysis of PDF documents, on the fly and incorporate it into a security stack. "On the fly" is key. PyDF2JSON simply creates a json structure out of PDF documents. It breaks a PDF document down into all its individual parts, and retains those parts for analysis. Once this is done, a more detailed analysis should be possible.

Installation
------------

Clone the repo and use it. Optionally, run python setup.py build/install to make the pydf2json module importable by all the things. You can also use pip install [--upgrade] pydf2json

Usage
-----

::

   > pydf.py -h
   usage: pydf.py [-h] [-d LOCATION] [--no_summary] [--show_json] [--show_ttf]
                  [--show_bitmap] [--show_pics] [--show_embedded_files]
                  pdf
  
   > pydf.py Docusign.pdf
   Summary of PDF attributes:
   --------------------------
   
   AA:                           0
   AcroForms:                    0
   Embedded Files:               0
   JS:                           0
   Launch:                       0
   Object Streams:               0
   OpenActions:                  0
   Pages:                        2
   
   URIs in document:
     O: 38 0       http://<redacted>.com/llp.php

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

1. pydf.py
    - Expand on the summary to include the following:
        - [w] Add the type of Launch and maybe trigger on some keywords like cmd.exe and .vbs to indicate malware.
        - [x] Possibly provide information on what objects contain js instead of just giving a count.

2. pydf2json.py
    - [x] Ongoing testing to see what breaks the json construction.
    - [x] More robust error checking. It is currently weak because I have mainly been concerned with making things work.
    - [x] Fix stream decoding: If stream decoding fails then store encoded stream instead of erroring out.
    - [w] Currently have only 2 functioning PNG decoders.
    - [D] Currently no TIFF decoder. Haven't come across a need to provide it.
    - [D] Stream extension processing is non-existent. Haven't come across a PDF that uses it yet.

3. LaikaBOSS module creation.
    - [ ] Code and test explode_pdf.py

- D = Don't care. After all the PDF's I've researched, I still have no reason to provide this capability.
- w = Working
- x = Done