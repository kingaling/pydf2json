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
        - [ ] Possibly provide information on what objects contain js instead of just giving a count.

2. pydf2json.py
    - [w] Ongoing testing to see what breaks the json construction.
    - [w] More robust error checking. It is currently weak because I have mainly been concerned with making things work.
    - [x] Fix stream decoding: If stream decoding fails then store encoded stream instead of erroring out.
    - [ ] Currently have only 2 functioning PNG decoders. I have only come across PDF's that use algo 1 and 2.
    - [ ] Currently no TIFF decoder. Haven't come across a need to provide it.
    - [ ] Stream extension processing is non-existent. Haven't come across a PDF that uses it yet.

3. LaikaBOSS module creation.
    - [ ] Code and test explode_pdf.py

- w = working
- x = done