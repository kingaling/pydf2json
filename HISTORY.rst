Recent Activity
---------------
20180801 - A couple things:
    - Added support for LZWDecode filter
        - Borrowed code from pdfminer.
          It's efficient, and until I can write my own (because I like doing that sort of thing) this will be used.
    - Started implemeting the malware index checks.
        - Checking for unecessary whitespace within object definitions
        - Checking for unecessary encoding of chars in obect definitions

History
-------
20180722 - Fixed Crypt filter logic
    - Discovered that the encryption key is calculated differently when a Crypt filter is used.
        - https://forums.adobe.com/thread/1938926

20180601 - Added decryption capabilities (Set version to 2.2.0)
    - Standard Security Handler Version 5; Revision 6
        - Tested code on AESV3 with no issues using user passwords, owner passwords and blank passwords
    - Code will exit upon discovering encryption if pycrypto modules have not been loaded
        - So please do 'pip install pycrypto'

20180526
    - Rewrote code that extracts EmbedddFiles and JavaScript summary info.

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