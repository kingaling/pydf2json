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
                    [--show_json]
                    pdf
  
   > pydf.py secure_dropbox.pdf -p 29576AE2
     Summary of PDF attributes:
     --------------------------

     Encrypted:                    True
     User Pass:                    None
     Key:                          030359FF89FC8A8EB764E97AD2ED7091
     Key Length:                   128 bits
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
pydf2json.py can be called from your own programs with ``import pydf2json``. See the `wiki <https://github.com/xamiel/pydf2json/wiki/pydf2json.py>`_.

Error Reporting
---------------

I am versed in the concept of OPSEC. If you have a PDF that this fails on / causes crash, Please send me the PDF in question if possible. No document sent to me will be shared with anyone at anytime and will be destroyed when I'm done testing with it. Archive it with a utility like 7Zip and encrypt it with the following password: ``fr74ed83e.dj#ifkk``

Send it to ``kingaling@meatchicken.net``
The password is simply to keep PDF from being scanned by AV. :)

My Reasons
----------

This code was inspired by my desire to have a pdf analysis module for the LaikaBOSS framework.
See: `LaikaBOSS <https://github.com/lmco/laikaboss>`_ developed by Lockheed Martin.



To Do
-----

1. Malware index
    - Need to work on the malware index described on line 186 of pydf2json.py
