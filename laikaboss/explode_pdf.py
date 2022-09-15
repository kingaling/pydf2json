# Created by Shane King <kingaling_at_meatchicken_dot_net>

import pydf2json
import pydf2json.scripts.pdfcrack as pcrack
from laikaboss.objectmodel import ModuleObject, ExternalVars
from laikaboss.si_module import SI_MODULE
from laikaboss import config
from laikaboss import gendict
from laikaboss.exclusions import domain as exdom
from laikaboss.exclusions import proto as exproto
import os
import shutil
import re


class EXPLODE_PDF(SI_MODULE):
    def __init__(self, ):
        self.module_name = "EXPLODE_PDF"
        self.TEMP_DIR = '/tmp/laikaboss_tmp'
        if hasattr(config, 'tempdir'):
            self.TEMP_DIR = config.tempdir.rstrip('/')
        if not os.path.isdir(self.TEMP_DIR):
            os.mkdir(self.TEMP_DIR)
            os.chmod(self.TEMP_DIR, 0777)

    def _run(self, scanObject, result, depth, args):
        moduleResult = []

        pdf_object = pydf2json.PyDF2JSON()
        crypto = pydf2json.PDFCrypto()
        pdf_object.dump_streams = False
        pdf_object.dump_loc = self.TEMP_DIR + '/' + scanObject.uuid
        pdf_object.max_size = 2 # Integer is in MB
        x = scanObject.buffer
        crypt_handler = pdf_object.get_encryption_handler(x)

        pdf_object.dump_streams = True
        if crypt_handler:
            pdf_password = ''
            target_type = 0
            pass_type = 0
            dict_index = 0
            body_txt = ''

            for i in result.files:
                if re.match('e_email_text/plain', result.files[i].filename):
                    body_txt += (result.files[i].buffer + ' ')
                if re.match('e_email_text/html', result.files[i].filename):
                    tmp_text = gendict.html2text(result.files[i].buffer)
                    body_txt += tmp_text
            dictionary = gendict.gen_dict(body_txt)

            # Set target type. This is the type of encryption used in doc.
            # The numbers correspond to hard coded algorithms defined in pdfcrack.py
            if crypt_handler['version'] == 5:
                target_type = 1
            if crypt_handler['version'] < 5 and crypt_handler['revision'] < 3:
                target_type = 2
            if crypt_handler['version'] < 5 and crypt_handler['revision'] >= 3:
                target_type = 3

            # We're only using digits for this
            charset = pcrack.gen_charset('d')

            # Brute force with digits or words found in email
            try:
                if crypt_handler['version'] == 5:
                    while True:
                        if crypto.authv6_U(pdf_password, crypt_handler['U']):
                            crypt_handler['file_key'] = crypto.retrv5_fkey(crypt_handler, pdf_password, 'User')
                            pdf_object.pdf_password = pdf_password
                            break
                        if pass_type == 2:
                            break
                        if pass_type == 0:
                            pass_type += 1
                            if len(dictionary) == 0:
                                pass_type += 1
                        if pass_type == 1 and dict_index <= len(dictionary):
                            # pdf_password = str(dictionary[dict_index])
                            # dict_index += 1
                            if dict_index == len(dictionary):
                                pass_type += 1
                            else:
                                pdf_password = str(dictionary[dict_index])
                                dict_index += 1
                                continue
                        if pass_type == 2:
                            pdf_password = pcrack.crack(crypt_handler, target_type, 1, 4, charset)
                            if not pdf_password:
                                break

                if crypt_handler['version'] < 5:
                    while True:
                        if crypt_handler['revision'] < 3:
                            tmpU_key = crypto.genv4r2_U_entry(crypt_handler, pdf_password)
                        else:
                            tmpU_key = crypto.genv4r34_U_entry(crypt_handler, pdf_password)
                        if tmpU_key[0:16] == crypt_handler['U'][0:16]:
                            crypt_handler['file_key'] = crypto.retrv4_fkey(crypt_handler, pdf_password)
                            pdf_object.pdf_password = pdf_password
                            break
                        if pass_type == 2:
                            break
                        if pass_type == 0:
                            pass_type += 1
                            if len(dictionary) == 0:
                                pass_type += 1
                        if pass_type == 1 and dict_index <= len(dictionary):
                            #pdf_password = str(dictionary[dict_index])
                            #dict_index += 1
                            if dict_index == len(dictionary):
                                pass_type += 1
                            else:
                                pdf_password = str(dictionary[dict_index])
                                dict_index += 1
                                continue
                        if pass_type == 2:
                            pdf_password = pcrack.crack(crypt_handler, target_type, 1, 4, charset)
                            if not pdf_password:
                                break

            except Exception as e:
                raise e

        try:
            pdf_object.GetPDF(x)
            summary = pdf_object.expose_summary()
        except pydf2json.MaxSizeExceeded:
            scanObject.addMetadata(self.module_name, 'ScanError', 'Max analysis size exceeded.')
            return moduleResult
        except Exception as e:
            scanObject.addMetadata(self.module_name, 'ScanError', e)
            shutil.rmtree(self.TEMP_DIR + '/' + scanObject.uuid)
            return moduleResult

        # If we have arrived here then...
        scanObject.addMetadata(self.module_name, 'ScanError', 'None')

        # Populate our metadata now.
        scanObject.addMetadata(self.module_name, 'Encryption', summary['Encryption']['enabled'])
        if summary['Encryption']['enabled']:
            scanObject.addMetadata(self.module_name, 'EncFileKey:', summary['Encryption']['file_key'])
            scanObject.addMetadata(self.module_name, 'EncKeyLength:', summary['Encryption']['key_length'])
            scanObject.addMetadata(self.module_name, 'EncAlgo:', summary['Encryption']['algorithm'])
            scanObject.addMetadata(self.module_name, 'DocPassword:', pdf_object.pdf_password)
        aa_num = 0
        aa_sections = {}
        for i in summary['Additional Actions']:
            i_len = len(summary['Additional Actions'][i])
            aa_num += i_len
            if i_len > 0:
                for j in summary['Additional Actions'][i]:
                    if not aa_sections.has_key(i):
                        aa_sections[i] = []
                    aa_sections[i].append(j)
        scanObject.addMetadata(self.module_name, 'AdditionalActions:', aa_num)
        scanObject.addMetadata(self.module_name, 'AcroForms:', summary['AcroForms'])
        scanObject.addMetadata(self.module_name, 'EmbeddedFiles:', len(summary['EmbeddedFiles']))
        scanObject.addMetadata(self.module_name, 'JS:', summary['JS'])
        scanObject.addMetadata(self.module_name, 'Launch:', len(summary['Launch']))
        scanObject.addMetadata(self.module_name, 'ObjectStreams:', summary['Object Streams'])
        scanObject.addMetadata(self.module_name, 'OpenActions:', summary['OpenActions'])
        scanObject.addMetadata(self.module_name, 'Pages:', summary['Pages'])
        if len(summary['Arbitrary Data']) > 0:
            scanObject.addMetadata(self.module_name, 'ArbitraryData:', summary['Arbitrary Data'])
        if len(summary['AcroForm Actions']) > 0:
            scanObject.addMetadata(self.module_name, 'AcroActions:', summary['AcroForm Actions'])
        if len(summary['Launch']) > 0:
            scanObject.addMetadata(self.module_name, 'LaunchActions:', summary['Launch'])
        if len(summary['Names']) > 0:
            if len(summary['EmbeddedFiles']) > 0:
                scanObject.addMetadata(self.module_name, 'EmbeddedFiles:', summary['EmbeddedFiles'])
            if len(summary['JavaScript']) > 0:
                scanObject.addMetadata(self.module_name, 'JavaScript:', summary['JavaScript'])
        if summary.has_key('Link Annotations'):
            if len(summary['Link Annotations']) > 0:
                tmp_link = []
                lnkcount = 0
                for i in summary['Link Annotations']:
                    for j in summary['Link Annotations'][i]:
                        if not re.match('javascript', j['Link']) and not j['Link'] in tmp_link \
                                and not exproto.match(j['Link']) and not exdom.match(j['Link']):
                            tmp_link.append(j['Link'])
                            scanObject.addFlag("url:pdf:" + j["Link"])
                            lnkcount += 1
                            if lnkcount >= 5: break
                    if lnkcount >= 5: break
                scanObject.addMetadata(self.module_name, 'Hyperlinks:', tmp_link)
        if aa_num > 0:
            for i in aa_sections:
                if i == 'acro_adds':
                    scanObject.addMetadata(self.module_name, 'AcroFormAA:', aa_sections[i])
                if i == 'annot_adds':
                    scanObject.addMetadata(self.module_name, 'AnnotationAA:', aa_sections[i])
                if i == 'page_adds':
                    scanObject.addMetadata(self.module_name, 'PageAA:', aa_sections[i])
                if i == 'cat_adds':
                    scanObject.addMetadata(self.module_name, 'CatalogAA:', aa_sections[i])

        # Read Malware Index:
        '''
        # Had to comment out all of this because 3rd party PDF creation applications don't give a DAMN about the specs
        # If you'd like thousands of F+ alerts, go ahead and uncomment this block :)
        # Also in pydf2json code I mentioned how this is pretty much a failure. See line 183 (I think) in that file.
        if summary['Malware Index'][7] > 5:
            scanObject.addFlag("pdf:malIndex:whitespace")
        if summary['Malware Index'][6] > 0:
            scanObject.addFlag("pdf:malIndex:objObfuscate")
        if summary['Malware Index'][5] > 5:
            scanObject.addFlag("pdf:malIndex:xrefAlign")
        '''

        # Add dumped streams to moduleResult and delete them from disk
        for i in summary['Dumped Files']:
            f_buffer = open(i, 'rb').read()
            moduleResult.append(ModuleObject(buffer=f_buffer,
                                             externalVars=ExternalVars(filename=i,
                                                                       contentType=['pdf_stream'])))
            os.remove(i)
        # Finished with streams

        shutil.rmtree(self.TEMP_DIR + '/' + scanObject.uuid)

        # Did we crack PDF? Add it to Laikas flag list so we can easily see password if we wish.
        if crypt_handler:
            if pass_type == 0: # PDF was encrypted with an owner pass only. The user password is blank.
                scanObject.addFlag("pdf:BlankPass")
            if pass_type == 1: # PDF was encrypted with a password that was found in the body of the email.
                scanObject.addFlag("pdf:DictionaryCrack:" + pdf_password)
            if pass_type == 2: # PDF was encrypted with 4 digits.
                scanObject.addFlag("pdf:BruteForceCrack:" + pdf_password)
        return moduleResult