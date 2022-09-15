Example LaikaBOSS Module
=========

explode_pdf.py is a module for LaikaBOSS. It is included here as an example of how to use the pydf2json code to parse PDFs that are found in emails. Assuming laika is deployed somewhere in a production environment where all emails are fed to it, this will rapidly parse any attached PDF's. It has a hardcoded value that limits it to 2MB documents so that you don't inadvertently choke your deployment. It will also automatically make a dictionary of words found in the document to try and crack it if it's encrypted. If that fails it will also try all variations of 4-digit numbers. Both of these are common schemes when sending encrypted PDFs by email.
