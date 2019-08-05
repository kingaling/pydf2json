# Copyright (C) 2018  Shane King <kingaling at meatchicken dot net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import re
import zlib
import hashlib
import random
import os
import sys
import struct
from tempfile import gettempdir
from platform import system as platform_sys
import pdfcrypt

try:
    # noinspection PyPackageRequirements
    from Crypto.Cipher import AES
except Exception as e:
    pass


__version__ = '2.2.3'
__author__ = 'Shane King <kingaling_at_meatchicken_dot_net>'


class SpecViolation(Exception):
    pass

class MaxSizeExceeded(Exception):
    pass

class LZWDecoder(object):
    # LZW code sourced from pdfminer
    # Copyright (c) 2004-2009 Yusuke Shinyama <yusuke at cs dot nyu dot edu>
    #
    # Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
    # documentation files (the "Software"), to deal in the Software without restriction, including without limitation
    # the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
    # and to permit persons to whom the Software is furnished to do so, subject to the following conditions: etc...

    # ** Modified code so importing StreamIO wasn't needed.

    def __init__(self, fp):
        self.fp = fp
        self.fpos = 0
        self.buff = 0
        self.bpos = 8
        self.nbits = 9
        self.table = None
        self.prevbuf = None
        return

    def readbits(self, bits):
        v = 0
        while 1:
            # the number of remaining bits we can get from the current buffer.
            r = 8-self.bpos
            if bits <= r:
                # |-----8-bits-----|
                # |-bpos-|-bits-|  |
                # |      |----r----|
                v = (v<<bits) | ((self.buff>>(r-bits)) & ((1<<bits)-1))
                self.bpos += bits
                break
            else:
                # |-----8-bits-----|
                # |-bpos-|---bits----...
                # |      |----r----|
                v = (v<<r) | (self.buff & ((1<<r)-1))
                bits -= r
                if self.fpos == len(self.fp):
                    raise EOFError
                x = self.fp[self.fpos]
                self.fpos += 1
                if not x: raise EOFError
                self.buff = ord(x)
                self.bpos = 0
        return v

    def feed(self, code):
        x = ''
        if code == 256:
            self.table = [ chr(c) for c in range(256) ] # 0-255
            self.table.append(None) # 256
            self.table.append(None) # 257
            self.prevbuf = ''
            self.nbits = 9
        elif code == 257:
            pass
        elif not self.prevbuf:
            x = self.prevbuf = self.table[code]
        else:
            if code < len(self.table):
                x = self.table[code]
                self.table.append(self.prevbuf+x[0])
            else:
                self.table.append(self.prevbuf+self.prevbuf[0])
                x = self.table[code]
            l = len(self.table)
            if l == 511:
                self.nbits = 10
            elif l == 1023:
                self.nbits = 11
            elif l == 2047:
                self.nbits = 12
            self.prevbuf = x
        return x

    def run(self):
        while 1:
            try:
                code = self.readbits(self.nbits)
            except EOFError:
                break
            x = self.feed(code)
            yield x
        return

class PyDF2JSON(object):

    # Instantiate pdf crypto functions
    crypto = pdfcrypt.PDFCrypto()

    # password: Use this password to decrypt document.
    pdf_password = ''

    # show_ttf: Place true type fonts streams in json output. Default is False.
    show_ttf = False

    # show_bitmaps: Place bitmap streams in json output. Default is False.
    show_bitmaps = False

    # show_pics: Place picture streams in json output. Default is False.
    show_pics = False

    # show_embedded_files: Pretty much all other types of files. Default is False.
    show_embedded_files = False

    # show_arbitrary: Arbitrary data found outside of any object. Default is False.
    show_arbitrary = False

    # show_text: Show any decoded text streams. Default is false.
    show_text = False

    # dump_streams: Dump streams to a temp location. Using this for LaikaBOSS objects.
    dump_streams = False

    # max_size: Set a maximum size limit. Most PDF's I have seen that are malicious were no bigger than 500K.
    # But we'll set it to 2MB. Takes integers only. All integers will be treated as MB.
    max_size = 2

    # temp_loc: Temp directory where temp files are created that we need to work with
    __chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    __temp_dir = "".join(random.sample(__chars, 16))

    if platform_sys() == 'Windows':
        __os_windows = True
        dump_loc = gettempdir() + '\\'
    else:
        __os_windows = False
        dump_loc = gettempdir() + '/'

    # Keeping score of the shenanigans
    __overall_mal_index = [0, 0, 0, 0, 0, 0, 0, 0]

    # is doc encrypted?
    __is_crypted = False
    __crypt_handler_info = dict()
    __crypt_handler_info['o_keys'] = {}
    __crypt_handler_info['o_ignore'] = []
    __crypt_handler_info['o_ignore'].append('NO_DECRYPT')

    # Malware Index:
    # Each index has a max value of 0xFF (255)

    # 00 00 00 00 00 00 00 00
    # |  |  |  |  |  |  |  |____ Unnecessary white space
    # |  |  |  |  |  |  |_______ Named object obfuscation.
    # |  |  |  |  |  |__________ Misaligned object locations *
    # |  |  |  |  |_____________ Not used yet (Javascript) *
    # |  |  |  |________________ Not used yet
    # |  |  |___________________ Not used yet
    # |  |______________________ Not used yet (Only 1 page and it contains Javascript) *
    # |_________________________ Not used yet

    # Starred items (*) will be calculated during __get_summary()


    def __error_control(self, etype, message, misc=''):
        if re.match('SpecViolation', etype):
            raise SpecViolation('SpecViolation' + '(' + message + ' (' + misc + ')' + ')')
        else:
            raise Exception('Exception' + '(' + message + ' (' + misc + ')' + ')')


    def GetPDF(self, x):
        PDF = {}
        summary = {}
        PDF['Size'] = len(x)
        # Check max_size. Convert size to MB
        if (PDF['Size'] / 1048576.0) > self.max_size:
            raise MaxSizeExceeded('PDF length exceeds ' + str(self.max_size) + 'MB. Aborting analysis.')

        if self.dump_streams:
            # Check path to ensure it ends with a \ or /:
            if self.__os_windows:
                if re.search('\\\$', self.dump_loc):
                    self.dump_loc = self.dump_loc + self.__temp_dir + '\\'
                else:
                    self.dump_loc = self.dump_loc + '\\' + self.__temp_dir + '\\'
            else:
                if re.search('/$', self.dump_loc):
                    self.dump_loc = self.dump_loc + self.__temp_dir + '/'
                else:
                    self.dump_loc = self.dump_loc + '/' + self.__temp_dir + '/'
            if not os.path.exists(self.dump_loc):
                os.makedirs(self.dump_loc)
            summary['Temp File Location'] = self.dump_loc
            summary['Dumped Files'] = []

        # Verify we have PDF here.
        try:
            PDF['Header'] = self.__header_scan(x)
        except Exception as e:
            raise e

        # Hash document
        PDF['Document Hashes'] = {}
        PDF['Document Hashes']['MD5'] = hashlib.md5(x).hexdigest().upper()
        PDF['Document Hashes']['SHA1'] = hashlib.sha1(x).hexdigest().upper()
        PDF['Document Hashes']['SHA256'] = hashlib.sha256(x).hexdigest().upper()

        # Find start point for reading body....
        if len(PDF['Header']) == 2:
            s_offset = PDF['Header']['Comment']['Length'] + PDF['Header']['Comment']['Offset'] + 1
        else:
            s_offset = PDF['Header']['Version']['Length'] + PDF['Header']['Version']['Offset'] + 1

        # Check for encryption
        # If found set global file key
        try:
            self.get_encryption_handler(x, summary, self.pdf_password)
        except Exception as e:
            raise e

        if self.__is_crypted:
            if not 'Crypto.Cipher.AES' in sys.modules:
                raise Exception('Missing pycrypto. pip install pycrypto')
            try:
                if self.__crypt_handler_info['version'] == 5:
                    # Check v5 password
                    if self.crypto.authv6_U(self.pdf_password, self.__crypt_handler_info['U']):
                        self.__crypt_handler_info['file_key'] = self.crypto.retrv5_fkey(self.__crypt_handler_info,
                                                                                        self.pdf_password, 'User')
                    elif self.crypto.authv6_O(self.pdf_password, self.__crypt_handler_info['O'],
                                              self.__crypt_handler_info['U']):
                        self.__crypt_handler_info['file_key'] = self.crypto.retrv5_fkey(self.__crypt_handler_info,
                                                                                        self.pdf_password, 'Owner')
                    else:
                        raise Exception('Encrypted document requires a password. Aborting analysis.')
                    if not self.crypto.authv6_Perms(self.__crypt_handler_info['P'], self.__crypt_handler_info['Perms'],
                                                self.__crypt_handler_info['file_key']):
                        raise Exception('Encrypted document Perms entry is malformed. Tampering?')
                if self.__crypt_handler_info['version'] < 5:
                    if self.__crypt_handler_info['revision'] < 3:
                        tmpU_key = self.crypto.genv4r2_U_entry(self.__crypt_handler_info, self.pdf_password)
                    else:
                        tmpU_key = self.crypto.genv4r34_U_entry(self.__crypt_handler_info, self.pdf_password)
                    tmpu_password = self.crypto.authv4_O(self.__crypt_handler_info, self.pdf_password)
                    if self.__crypt_handler_info['revision'] < 3:
                        tmpO_key = self.crypto.genv4r2_U_entry(self.__crypt_handler_info, tmpu_password)
                    else:
                        tmpO_key = self.crypto.genv4r34_U_entry(self.__crypt_handler_info, tmpu_password)
                    if tmpU_key == self.__crypt_handler_info['U']:
                        self.__crypt_handler_info['file_key'] = self.crypto.retrv4_fkey(self.__crypt_handler_info, self.pdf_password)
                    elif tmpO_key == self.__crypt_handler_info['U']:
                        self.__crypt_handler_info['file_key'] = self.crypto.retrv4_fkey(self.__crypt_handler_info, tmpu_password)
                    else:
                        raise Exception('Encrypted document requires a password. Aborting analysis.')
            except Exception as e:
                raise e

        # Proceed with PDF body processing
        try:
            self.__overall_mal_index = [0, 0, 0, 0, 0, 0, 0, 0]
            PDF['Body'] = self.__body_scan(x, s_offset, summary)
        except Exception as e:
            raise e

        #PDF['Body'] = self.__body_scan(x, s_offset) # Debugging...
        # The above line got all indirect objects, trailers, xref tables etc
        # and preserved the position and length of all streams.
        # Now go get the streams... :)
        try:
            self.__process_streams(x, PDF['Body'], summary)
        except Exception as e:
            raise e

         # Create object map.
        omap = {}
        omap['IO'] = {}
        omap['OS'] = {}
        omap['IO Offsets'] = {}
        omap['XRT Offsets'] = []
        omap['XRS Offsets'] = []
        self.__assemble_map(PDF['Body'], omap)

        # Assemble a summary of things.
        try:
            ret = self.__get_summary(PDF, summary, omap)
        except Exception as e:
            raise e

        summary['Malware Index'] = self.__overall_mal_index
        return PDF, omap, summary


    def __process_arbitrary_data(self, arb):
        arb_data = arb
        try:
            c_len = len(arb[:24])
        except:
            c_len = len(arb)
        arb_len = len(arb)
        # Check for some basic data obfuscation:
        # Check 1st 24 chars for 6 bytes in a row of '\x00' style byte encoding
        if re.match('(\\\\x[0-9a-z]{2}){6}', arb[:c_len], re.IGNORECASE):
            arb_data = arb.replace('\\x', '')
            arb_data = arb_data.replace('\x00', '')
            arb_data = arb_data.replace('\x09', '')
            arb_data = arb_data.replace('\x0A', '')
            arb_data = arb_data.replace('\x0D', '')
            arb_data = arb_data.replace('\x20', '')
            arb_data = arb_data.decode('hex')

        arb_type = self.__identify_stream(arb_data)
        if arb_type == '':
            arb_type = 'Unknown'
        return arb_type, arb_data


    def __get_summary(self, pdf, summary, omap):
        processed_objects = []

        def __find_root():
            # Find the root objects via trailer entry...
            root_objects = []
            xref_entries = []
            if pdf['Body'].has_key('Trailers'):
                for i in range(0, len(pdf['Body']['Trailers'])):
                    if pdf['Body']['Trailers'][i]['Value'].has_key('Root'):
                        root_entry = pdf['Body']['Trailers'][i]['Value']['Root']['Value'].replace(' R', '')
                        if not root_entry in root_objects:
                            root_objects.append(root_entry)

            if not pdf['Body'].has_key('Start XRef Entries'):
                self.__error_control('SpecViolation', 'startxref entry is missing')

            for i in pdf['Body']['Start XRef Entries']:
                if not i == str(0): # Dummy xref table pointer for linear PDF's on page 1 of document.
                    xref_entries.append(int(i))

            if len(xref_entries) < 1:
                self.__error_control('SpecViolation', 'startxref entry is missing')

            # Go find more root objects
            for i in xref_entries:
                # Check map for this offset. If it's not found, xref tables are mis-aligned and this is probably malware.
                if not omap['IO Offsets'].has_key(i) and not i in omap['XRT Offsets']:
                    self.__update_mal_index(1, 5)

            if pdf['Body'].has_key('XRef Streams'):
                #back_ref = []
                for i in range(0, len(pdf['Body']['XRef Streams'])):
                    entry_len = len(pdf['Body']['XRef Streams'][i])
                    back_ref = pdf['Body']['XRef Streams'][i][entry_len - 1]['Back Ref']
                    if omap['IO'].has_key(back_ref):
                        for j in range(0, len(omap['IO'][back_ref])):
                            if not omap['IO'][back_ref][j][1] in xref_entries:
                                xref_entries.append(omap['IO'][back_ref][j][1])
                                # The last offset in xref_entry is the active one.

            # Add entries to root_obects
            for i in xref_entries:
                if omap['IO Offsets'].has_key(i):
                    obj = omap['IO Offsets'][i]
                    io_entry = omap['IO'][obj]
                    for j in range(0, len(io_entry)):
                        io_index = io_entry[j][0]
                        if type(pdf['Body']['Indirect Objects'][io_index][obj]['Value']) == dict:
                            if pdf['Body']['Indirect Objects'][io_index][obj]['Value'].has_key('Root'):
                                tmp_root_obj = pdf['Body']['Indirect Objects'][io_index][obj]['Value']['Root']['Value'].replace(' R', '')
                                if not tmp_root_obj in root_objects:
                                    root_objects.append(tmp_root_obj)

            if  len(root_objects) == 0:
                self.__error_control('SpecViolation', 'Required \'Root\' entry missing.')

            return root_objects, xref_entries


        def __get_catalog_data():
            def __catalog_additional_actions(c_actions):
                cat_adds = {}
                if type(c_actions) == list:
                    for i in c_actions:
                        __catalog_additional_actions(i)
                    return
                if type(c_actions) == dict:
                    if c_actions.has_key('WC'):
                        if c_actions['WC']['Value Type'] == 'Indirect Reference':
                            wc_temp = c_actions['WC']['Value'].replace(' R', '')
                            wc_map = self.__map_object(pdf['Body'], omap, wc_temp, None, True)
                            for i in wc_map:
                                for j in range(0, len(wc_map[i])):
                                    wc_val = __catalog_additional_actions(wc_map[i][j]['Value']['Value'])
                                    cat_adds['WC'] = {wc_temp: wc_val}
                        if c_actions['WC']['Value Type'] == 'Dictionary':
                            __catalog_additional_actions(c_actions['WC']['Value'])
                    if c_actions.has_key('WS'):
                        if c_actions['WS']['Value Type'] == 'Indirect Reference':
                            ws_temp = c_actions['WS']['Value'].replace(' R', '')
                            ws_map = self.__map_object(pdf['Body'], omap, ws_temp, None, True)
                            for i in ws_map:
                                for j in range(0, len(ws_map[i])):
                                    ws_val = __catalog_additional_actions(ws_map[i][j]['Value']['Value'])
                                    cat_adds['WS'] = {ws_temp: ws_val}
                        if c_actions['WS']['Value Type'] == 'Dictionary':
                            __catalog_additional_actions(c_actions['WS']['Value'])
                    if c_actions.has_key('DS'):
                        if c_actions['DS']['Value Type'] == 'Indirect Reference':
                            ds_temp = c_actions['DS']['Value'].replace(' R', '')
                            ds_map = self.__map_object(pdf['Body'], omap, ds_temp, None, True)
                            for i in ds_map:
                                for j in range(0, len(ds_map[i])):
                                    ds_val = __catalog_additional_actions(ds_map[i][j]['Value']['Value'])
                                    cat_adds['DS'] = {ds_temp: ds_val}
                        if c_actions['DS']['Value Type'] == 'Dictionary':
                            __catalog_additional_actions(c_actions['DS']['Value'])
                    if c_actions.has_key('WP'):
                        if c_actions['WP']['Value Type'] == 'Indirect Reference':
                            wp_temp = c_actions['WP']['Value'].replace(' R', '')
                            wp_map = self.__map_object(pdf['Body'], omap, wp_temp, None, True)
                            for i in wp_map:
                                for j in range(0, len(wp_map[i])):
                                    wp_val = __catalog_additional_actions(wp_map[i][j]['Value']['Value'])
                                    cat_adds['WP'] = {wp_temp: wp_val}
                        if c_actions['WP']['Value Type'] == 'Dictionary':
                            __catalog_additional_actions(c_actions['WP']['Value'])
                    if c_actions.has_key('DP'):
                        if c_actions['DP']['Value Type'] == 'Indirect Reference':
                            dp_temp = c_actions['DP']['Value'].replace(' R', '')
                            dp_map = self.__map_object(pdf['Body'], omap, dp_temp, None, True)
                            for i in dp_map:
                                for j in range(0, len(dp_map[i])):
                                    dp_val = __catalog_additional_actions(dp_map[i][j]['Value']['Value'])
                                    cat_adds['DP'] = {dp_temp: dp_val}
                        if c_actions['DP']['Value Type'] == 'Dictionary':
                            __catalog_additional_actions(c_actions['DP']['Value'])
                    if c_actions.has_key('JS'):
                        js.append(c_actions['JS']['Value'])
                        if c_actions['JS']['Value Type'] == 'Indirect Reference':
                            js_temp = c_actions['JS']['Value'].replace(' R', '')
                            __catalog_additional_actions(js_temp)
                        if c_actions['JS']['Value Type'] == 'Literal String':
                            return c_actions['JS']['Value']
                return cat_adds

            # Make sure we're dealing with objects of type 'catalog'
            io_indexes = []
            os_indexes = []

            cat_a = []
            acroforms = []
            names = []
            openactions = []
            outlines = []
            pages = []
            uris = []
            metadata = []

            for i in root_objects:
                processed_objects.append(i)
                root_map = self.__map_object(pdf['Body'], omap, i, None)
                for j in root_map:
                    for k in range(0, len(root_map[j])):
                        cat_index = root_map[j][k]['Index']

                        if pdf['Body'][j][cat_index][i]['Value']['Type']['Value'] == 'Catalog':
                            if pdf['Body'][j][cat_index][i]['Value'].has_key('Pages'):
                                pages.append(pdf['Body'][j][cat_index][i]['Value']['Pages']['Value'].replace(' R', ''))
                            else:
                                self.__error_control('SpecViolation', 'Required \'Pages\' entry missing.')

                            if pdf['Body'][j][cat_index][i]['Value'].has_key('AcroForm'):
                                if pdf['Body'][j][cat_index][i]['Value']['AcroForm']['Value Type'] == 'Indirect Reference':
                                    acro_ref = pdf['Body'][j][cat_index][i]['Value']['AcroForm']['Value'].replace(' R', '')
                                    processed_objects.append(acro_ref)
                                    acro_val = self.__map_object(pdf['Body'], omap, acro_ref, None, True)
                                    for l in acro_val:
                                        for m in range(0, len(acro_val[l])):
                                            acroforms.append(acro_val[l][m]['Value']['Value'])
                                if pdf['Body'][j][cat_index][i]['Value']['AcroForm']['Value Type'] == 'Dictionary':
                                    acroforms.append(pdf['Body'][j][cat_index][i]['Value']['AcroForm']['Value'])

                            if pdf['Body'][j][cat_index][i]['Value'].has_key('OpenAction'):
                                openactions.append(pdf['Body'][j][cat_index][i]['Value']['OpenAction'])

                            if pdf['Body'][j][cat_index][i]['Value'].has_key('Names'):
                                names.append(pdf['Body'][j][cat_index][i]['Value']['Names'])

                            if pdf['Body'][j][cat_index][i]['Value'].has_key('Outlines'):
                                outlines.append(pdf['Body'][j][cat_index][i]['Value']['Outlines']['Value'])

                            if pdf['Body'][j][cat_index][i]['Value'].has_key('URI'):
                                uris.append(pdf['Body'][j][cat_index][i]['Value']['URI']['Value'])

                            if pdf['Body'][j][cat_index][i]['Value'].has_key('AA'):
                                #cat_a.append(pdf['Body'][j][cat_index][i]['Value']['AA']['Value'])
                                acts = __catalog_additional_actions(pdf['Body'][j][cat_index][i]['Value']['AA']['Value'])
                                aa['cat_adds'].append({i: acts})
                        else:
                            self.__error_control('SpecViolation', 'Required \'Catalog\' entry missing.')

            #return pages, names, outlines, openactions, acroforms, uris, cat_a
            return pages, names, outlines, openactions, acroforms, uris


        def __get_pagecount():
            p_entry = pages[-1:][0]
            pagecount = None
            if omap['IO'].has_key(p_entry):
                index = omap['IO'][p_entry][-1:][0][0]
                if pdf['Body']['Indirect Objects'][index][p_entry]['Value'].has_key('Count'):
                    if pdf['Body']['Indirect Objects'][index][p_entry]['Value']['Count']['Value Type'] == 'Unknown':
                        pagecount = int(pdf['Body']['Indirect Objects'][index][p_entry]['Value']['Count']['Value'])
                    if pdf['Body']['Indirect Objects'][index][p_entry]['Value']['Count']['Value Type'] == 'Indirect Reference':
                        ir_index = pdf['Body']['Indirect Objects'][index][p_entry]['Value']['Count']['Value'].replace(' R', '')
                        raise Exception('Fix loop in __get_pagecount for indirect object trace')
            if omap['OS'].has_key(p_entry):
                index = omap['OS'][p_entry][-1:][0][0]
                if pdf['Body']['Object Streams'][index][p_entry]['Value'].has_key('Count'):
                    if pdf['Body']['Object Streams'][index][p_entry]['Value']['Count']['Value Type'] == 'Unknown':
                        pagecount = int(pdf['Body']['Object Streams'][index][p_entry]['Value']['Count']['Value'])
                    if pdf['Body']['Object Streams'][index][p_entry]['Value']['Count']['Value Type'] == 'Indirect Reference':
                        ir_index = pdf['Body']['Object Streams'][index][p_entry]['Value']['Count']['Value'].replace(' R', '')
                        raise Exception('Fix loop in __get_pagecount for indirect object trace')
            if pagecount == None:
                raise Exception('No pages found')
            return pagecount


        def __process_pages(obj):
            def __page_additional_actions(p_actions):
                page_adds = {}
                if type(p_actions) == list:
                    for i in p_actions:
                        __page_additional_actions(i)
                    return
                if type(p_actions) == dict:
                    if p_actions.has_key('O'):
                        if p_actions['O']['Value Type'] == 'Indirect Reference':
                            o_temp = p_actions['O']['Value'].replace(' R', '')
                            o_map = self.__map_object(pdf['Body'], omap, o_temp, None, True)
                            for i in o_map:
                                for j in range(0, len(o_map[i])):
                                    o_val = __page_additional_actions(o_map[i][j]['Value']['Value'])
                                    page_adds['O'] = {o_temp: o_val}
                        if p_actions['O']['Value Type'] == 'Dictionary':
                            __page_additional_actions(p_actions['O']['Value'])
                    if p_actions.has_key('C'):
                        if p_actions['C']['Value Type'] == 'Indirect Reference':
                            c_temp = p_actions['C']['Value'].replace(' R', '')
                            c_map = self.__map_object(pdf['Body'], omap, c_temp, None, True)
                            for i in c_map:
                                for j in range(0, len(c_map[i])):
                                    c_val = __page_additional_actions(c_map[i][j]['Value']['Value'])
                                    page_adds['C'] = {c_temp: c_val}
                        if p_actions['C']['Value Type'] == 'Dictionary':
                            __page_additional_actions(p_actions['C']['Value'])
                    if p_actions.has_key('JS'):
                        js.append(p_actions['JS']['Value'])
                        if p_actions['JS']['Value Type'] == 'Indirect Reference':
                            js_temp = p_actions['JS']['Value'].replace(' R', '')
                            __page_additional_actions(js_temp)
                        if p_actions['JS']['Value Type'] == 'Literal String':
                            return p_actions['JS']['Value']
                return page_adds


            def __process_annots(annots, page):
                def __annot_additional_actions(an_actions):
                    annot_adds = {}
                    if type(an_actions) == list:
                        for i in an_actions:
                            __annot_additional_actions(i)
                        return
                    if type(an_actions) == dict:
                        if an_actions.has_key('E'):
                            if an_actions['E']['Value Type'] == 'Indirect Reference':
                                e_temp = an_actions['E']['Value'].replace(' R', '')
                                e_map = self.__map_object(pdf['Body'], omap, e_temp, None, True)
                                for i in e_map:
                                    for j in range(0, len(e_map[i])):
                                        e_val = __annot_additional_actions(e_map[i][j]['Value']['Value'])
                                        annot_adds['E'] = {e_temp: e_val}
                            if an_actions['E']['Value Type'] == 'Dictionary':
                                __annot_additional_actions(an_actions['E']['Value'])
                        if an_actions.has_key('X'):
                            if an_actions['X']['Value Type'] == 'Indirect Reference':
                                x_temp = an_actions['X']['Value'].replace(' R', '')
                                x_map = self.__map_object(pdf['Body'], omap, x_temp, None, True)
                                for i in x_map:
                                    for j in range(0, len(x_map[i])):
                                        x_val = __annot_additional_actions(x_map[i][j]['Value']['Value'])
                                        annot_adds['X'] = {x_temp: x_val}
                            if an_actions['X']['Value Type'] == 'Dictionary':
                                __annot_additional_actions(an_actions['X']['Value'])
                        if an_actions.has_key('D'):
                            if an_actions['D']['Value Type'] == 'Indirect Reference':
                                d_temp = an_actions['D']['Value'].replace(' R', '')
                                d_map = self.__map_object(pdf['Body'], omap, d_temp, None, True)
                                for i in d_map:
                                    for j in range(0, len(d_map[i])):
                                        d_val = __annot_additional_actions(d_map[i][j]['Value']['Value'])
                                        annot_adds['D'] = {d_temp: d_val}
                            if an_actions['D']['Value Type'] == 'Dictionary':
                                __annot_additional_actions(an_actions['D']['Value'])
                        if an_actions.has_key('U'):
                            if an_actions['U']['Value Type'] == 'Indirect Reference':
                                u_temp = an_actions['U']['Value'].replace(' R', '')
                                u_map = self.__map_object(pdf['Body'], omap, u_temp, None, True)
                                for i in u_map:
                                    for j in range(0, len(u_map[i])):
                                        u_val = __annot_additional_actions(u_map[i][j]['Value']['Value'])
                                        annot_adds['U'] = {u_temp: u_val}
                            if an_actions['U']['Value Type'] == 'Dictionary':
                                __annot_additional_actions(an_actions['U']['Value'])
                        if an_actions.has_key('Fo'):
                            if an_actions['Fo']['Value Type'] == 'Indirect Reference':
                                fo_temp = an_actions['Fo']['Value'].replace(' R', '')
                                fo_map = self.__map_object(pdf['Body'], omap, fo_temp, None, True)
                                for i in fo_map:
                                    for j in range(0, len(fo_map[i])):
                                        fo_val = __annot_additional_actions(fo_map[i][j]['Value']['Value'])
                                        annot_adds['Fo'] = {fo_temp: fo_val}
                            if an_actions['Fo']['Value Type'] == 'Dictionary':
                                __annot_additional_actions(an_actions['Fo']['Value'])
                        if an_actions.has_key('Bl'):
                            if an_actions['Bl']['Value Type'] == 'Indirect Reference':
                                bl_temp = an_actions['Bl']['Value'].replace(' R', '')
                                bl_map = self.__map_object(pdf['Body'], omap, bl_temp, None, True)
                                for i in bl_map:
                                    for j in range(0, len(bl_map[i])):
                                        bl_val = __annot_additional_actions(bl_map[i][j]['Value']['Value'])
                                        annot_adds['Bl'] = {bl_temp: bl_val}
                            if an_actions['Bl']['Value Type'] == 'Dictionary':
                                __annot_additional_actions(an_actions['Bl']['Value'])
                        if an_actions.has_key('PO'):
                            if an_actions['PO']['Value Type'] == 'Indirect Reference':
                                po_temp = an_actions['PO']['Value'].replace(' R', '')
                                po_map = self.__map_object(pdf['Body'], omap, po_temp, None, True)
                                for i in po_map:
                                    for j in range(0, len(po_map[i])):
                                        po_val = __annot_additional_actions(po_map[i][j]['Value']['Value'])
                                        annot_adds['PO'] = {po_temp: po_val}
                            if an_actions['PO']['Value Type'] == 'Dictionary':
                                __annot_additional_actions(an_actions['PO']['Value'])
                        if an_actions.has_key('PC'):
                            if an_actions['PC']['Value Type'] == 'Indirect Reference':
                                pc_temp = an_actions['PC']['Value'].replace(' R', '')
                                pc_map = self.__map_object(pdf['Body'], omap, pc_temp, None, True)
                                for i in pc_map:
                                    for j in range(0, len(pc_map[i])):
                                        pc_val = __annot_additional_actions(pc_map[i][j]['Value']['Value'])
                                        annot_adds['PC'] = {pc_temp: pc_val}
                            if an_actions['PC']['Value Type'] == 'Dictionary':
                                __annot_additional_actions(an_actions['PC']['Value'])
                        if an_actions.has_key('PV'):
                            if an_actions['PV']['Value Type'] == 'Indirect Reference':
                                pv_temp = an_actions['PV']['Value'].replace(' R', '')
                                pv_map = self.__map_object(pdf['Body'], omap, pv_temp, None, True)
                                for i in pv_map:
                                    for j in range(0, len(pv_map[i])):
                                        pv_val = __annot_additional_actions(pv_map[i][j]['Value']['Value'])
                                        annot_adds['PV'] = {pv_temp: pv_val}
                            if an_actions['PV']['Value Type'] == 'Dictionary':
                                __annot_additional_actions(an_actions['PV']['Value'])
                        if an_actions.has_key('PI'):
                            if an_actions['PI']['Value Type'] == 'Indirect Reference':
                                pi_temp = an_actions['PI']['Value'].replace(' R', '')
                                pi_map = self.__map_object(pdf['Body'], omap, pi_temp, None, True)
                                for i in pi_map:
                                    for j in range(0, len(pi_map[i])):
                                        pi_val = __annot_additional_actions(pi_map[i][j]['Value']['Value'])
                                        annot_adds['PI'] = {pi_temp: pi_val}
                            if an_actions['PI']['Value Type'] == 'Dictionary':
                                __annot_additional_actions(an_actions['PI']['Value'])
                        if an_actions.has_key('JS'):
                            js.append(an_actions['JS']['Value'])
                            if an_actions['JS']['Value Type'] == 'Indirect Reference':
                                js_temp = an_actions['JS']['Value'].replace(' R', '')
                                __annot_additional_actions(js_temp)
                            if an_actions['JS']['Value Type'] == 'Literal String':
                                return an_actions['JS']['Value']
                    return annot_adds


                def __get_dimensions(rect):
                    if type(rect) == list:
                        for i in range(0, len(rect)):
                            if rect[i]['Value Type'] == 'Unknown':
                                rect_area.append(float(rect[i]['Value']))
                            if rect[i]['Value Type'] == 'Indirect Reference':
                                rect_val = rect[i]['Value'].replace(' R', '')
                                rect_map = self.__map_object(pdf['Body'], omap, rect_val, None, True)
                                processed_objects.append(rect_val)
                                for i in rect_map:
                                    for j in range(0, len(rect_map[i])):
                                        __get_dimensions(rect_map[i][j]['Value']['Value'])
                    if type(rect) == dict:
                        if rect['Value Type'] == 'Indirect Reference':
                            rect_val = rect['Value'].replace(' R', '')
                            rect_map = self.__map_object(pdf['Body'], omap, rect_val, None, True)
                            processed_objects.append(rect_val)
                            for i in rect_map:
                                for j in range(0, len(rect_map[i])):
                                    __get_dimensions(rect_map[i][j]['Value']['Value'])
                        if rect['Value Type'] == 'Array':
                            for i in range(0, len(rect['Value'])):
                                __get_dimensions(rect['Value'][i])
                        if rect['Value Type'] == 'Unknown':
                            rect_area.append(float(rect['Value']))
                    if type(rect) == str:
                        rect_area.append(float(rect))
                    return


                def __get_hyperlink(a):
                    sub_type = []
                    uri = []

                    if a['Value Type'] == 'Literal String':
                        uri.append(a['Value'])
                    if a['Value Type'] == 'Dictionary':
                        if a['Value'].has_key('S'):
                            if a['Value']['S']['Value Type'] == 'Named Object':
                                sub_type.append(a['Value']['S']['Value'])
                        if a['Value'].has_key('URI'):
                            if a['Value']['URI']['Value Type'] == 'Literal String':
                                uri.append(a['Value']['URI']['Value'])
                            if a['Value']['URI']['Value Type'] == 'Indirect Reference':
                                a_ref = a['Value']['URI']['Value'].replace(' R', '')
                                a_map = self.__map_object(pdf['Body'], omap, a_ref, None, True)
                                processed_objects.append(a_ref)
                                for j in a_map:
                                    for k in range(0, len(a_map[j])):
                                        temp_sub_type, uri = __get_hyperlink(a_map[j][k]['Value'])
                                        if len(uri) == 1:
                                            if not summary['Link Annotations'].has_key(page):
                                                summary['Link Annotations'][page] = []
                                            summary['Link Annotations'][page].append({'Link': uri[0], 'Dimensions': rect_area})
                                            temp_sub_type = ''
                                            uri = []

                    if a['Value Type'] == 'Indirect Reference':
                        a_ref = a['Value'].replace(' R', '')
                        a_map = self.__map_object(pdf['Body'], omap, a_ref, None, True)
                        processed_objects.append(a_ref)
                        for j in a_map:
                            for k in range(0, len(a_map[j])):
                                sub_type, uri = __get_hyperlink(a_map[j][k]['Value'])
                                if len(uri) == 1:
                                    if not summary['Link Annotations'].has_key(page):
                                        summary['Link Annotations'][page] = []
                                    summary['Link Annotations'][page].append({'Link': uri[0], 'Dimensions': rect_area})
                                    sub_type = []
                                    uri = []
                    return sub_type, uri


                if type(annots) == list:
                    for i in annots:
                        __process_annots(i, page)
                    return
                if annots.has_key('Value Type'):
                    if annots['Value Type'] == 'Indirect Reference':
                        annots_ref = annots['Value'].replace(' R', '')
                        # Map it
                        if not annots_ref in processed_objects:
                            map_res = self.__map_object(pdf['Body'], omap, annots_ref, None, True)
                            processed_objects.append(annots_ref)
                            for i in map_res:
                                for j in range(0, len(map_res[i])):
                                    annots_value = map_res[i][j]['Value']
                                    __process_annots(annots_value, page)
                        else:
                            return
                    if annots['Value Type'] == 'Dictionary':
                        __process_annots(annots['Value'], page)
                    if annots['Value Type'] == 'Array':
                        __process_annots(annots['Value'], page)
                        return
                if annots.has_key('Subtype'):
                    if annots['Subtype']['Value'] == 'Link' and annots.has_key('Rect'):
                        rect_area = []
                        __get_dimensions(annots['Rect'])
                        uri = []
                        sub_type = []

                        if not summary.has_key('Link Annotations'):
                            summary['Link Annotations'] = {}

                        if annots.has_key('A'):
                            sub_type, uri = __get_hyperlink(annots['A'])


                        if len(uri) == 1 and len(sub_type) == 1 and len(rect_area) == 4:
                            if not summary['Link Annotations'].has_key(page):
                                summary['Link Annotations'][page] = []
                            summary['Link Annotations'][page].append({'Link': uri[0], 'Dimensions': rect_area})
                if annots.has_key('AA'):
                    acts = __annot_additional_actions(annots['AA']['Value'])
                    aa['annot_adds'].append(acts)
                return


            if type(obj) == list:
                for i in range(0, len(obj)):
                    if type(obj[i]) == dict:
                        __process_pages(obj[i])
                    if type(obj[i]) == str:
                        if not obj[i] in processed_objects:
                            processed_objects.append(obj[i])
                            page_map = self.__map_object(pdf['Body'], omap, obj[i], None, True)
                            for j in page_map:
                                for k in range(0, len(page_map[j])):
                                    page_value = page_map[j][k]['Value']['Value']
                                    if page_value.has_key('Annots'):
                                        if j == 'Object Streams':
                                            o_type = 'O'
                                        else:
                                            o_type = 'I'
                                        o_idx = str(page_map[j][k]['Index'])
                                        k_spl = obj[i].split(' ')
                                        o_obj = k_spl[0]
                                        o_gen = k_spl[1]
                                        o_off = str(page_map[j][k]['Value']['Offset'])
                                        page_number = o_type + '.' + o_idx + '.' + o_obj + '.' + o_gen + '.' + o_off
                                        __process_annots(page_value['Annots'], page_number)
                                    if page_value.has_key('Kids'):
                                        __process_pages(page_value['Kids'])
                                    if page_value.has_key('AA'):
                                        acts = __page_additional_actions(page_value['AA']['Value'])
                                        aa['page_adds'].append({obj[i]: acts})
            if type(obj) == dict:
                if obj.has_key('Value Type'):
                    if obj['Value Type'] == 'Array':
                        __process_pages(obj['Value'])
                    if obj['Value Type'] == 'Indirect Reference':
                        kids_value = obj['Value'].replace(' R', '')
                        page_map = self.__map_object(pdf['Body'], omap, kids_value, None, True)
                        for j in page_map:
                            for k in range(0, len(page_map[j])):
                                page_value = page_map[j][k]['Value']['Value']
                                if page_value.has_key('Annots'):
                                    if j == 'Object Streams':
                                        o_type = 'O'
                                    else:
                                        o_type = 'I'
                                    o_idx = str(page_map[j][k]['Index'])
                                    k_spl = kids_value.split(' ')
                                    o_obj = k_spl[0]
                                    o_gen = k_spl[1]
                                    o_off = str(page_map[j][k]['Value']['Offset'])
                                    page_number = o_type + '.' + o_idx + '.' + o_obj + '.' + o_gen + '.' + o_off
                                    __process_annots(page_value['Annots'], page_number)
                                if page_value.has_key('Kids'):
                                    __process_pages(page_value['Kids'])
                                if page_value.has_key('AA'):
                                    acts = __page_additional_actions(page_value['AA']['Value'])
                                    aa['page_adds'].append({kids_value: acts})
            return


        def __process_acroforms(acros):
            def __form_additional_actions(a_actions):
                acro_adds = {}
                if type(a_actions) == list:
                    for i in a_actions:
                        __form_additional_actions(i)
                    return
                if type(a_actions) == dict:
                    if a_actions.has_key('F'):
                        if a_actions['F']['Value Type'] == 'Indirect Reference':
                            f_temp = a_actions['F']['Value'].replace(' R', '')
                            f_map = self.__map_object(pdf['Body'], omap, f_temp, None, True)
                            for i in f_map:
                                for j in range(0, len(f_map[i])):
                                    f_val = __form_additional_actions(f_map[i][j]['Value']['Value'])
                                    acro_adds['F'] = {f_temp: f_val}
                        if a_actions['F']['Value Type'] == 'Dictionary':
                            __form_additional_actions(a_actions['F']['Value'])
                    if a_actions.has_key('K'):
                        if a_actions['K']['Value Type'] == 'Indirect Reference':
                            k_temp = a_actions['K']['Value'].replace(' R', '')
                            k_map = self.__map_object(pdf['Body'], omap, k_temp, None, True)
                            for i in k_map:
                                for j in range(0, len(k_map[i])):
                                    k_val = __form_additional_actions(k_map[i][j]['Value']['Value'])
                                    acro_adds['K'] = {k_temp: k_val}
                        if a_actions['K']['Value Type'] == 'Dictionary':
                            __form_additional_actions(a_actions['K']['Value'])
                    if a_actions.has_key('V'):
                        if a_actions['V']['Value Type'] == 'Indirect Reference':
                            v_temp = a_actions['V']['Value'].replace(' R', '')
                            v_map = self.__map_object(pdf['Body'], omap, v_temp, None, True)
                            for i in v_map:
                                for j in range(0, len(v_map[i])):
                                    v_val = __form_additional_actions(v_map[i][j]['Value']['Value'])
                                    acro_adds['V'] = {v_temp: v_val}
                        if a_actions['V']['Value Type'] == 'Dictionary':
                            __form_additional_actions(a_actions['V']['Value'])
                    if a_actions.has_key('C'):
                        if a_actions['C']['Value Type'] == 'Indirect Reference':
                            c_temp = a_actions['C']['Value'].replace(' R', '')
                            c_map = self.__map_object(pdf['Body'], omap, c_temp, None, True)
                            for i in c_map:
                                for j in range(0, len(c_map[i])):
                                    c_val = __form_additional_actions(c_map[i][j]['Value']['Value'])
                                    acro_adds['C'] = {c_temp: c_val}
                        if a_actions['C']['Value Type'] == 'Dictionary':
                            __form_additional_actions(a_actions['C']['Value'])
                    if a_actions.has_key('JS'):
                        js.append(a_actions['JS']['Value'])
                        if a_actions['JS']['Value Type'] == 'Indirect Reference':
                            js_temp = a_actions['JS']['Value'].replace(' R', '')
                            __form_additional_actions(js_temp)
                        if a_actions['JS']['Value Type'] == 'Literal String':
                            return a_actions['JS']['Value']
                return acro_adds


            def __field_check(acros):
                if type(acros) == list:
                    for i in acros:
                        x = __field_check(i)
                        if x == True:
                            return True

                if type(acros) == dict:
                    if acros.has_key('Fields'):
                        if acros['Fields']['Value Type'] == 'Array':
                            if len(acros['Fields']['Value']) > 0:
                                for i in acros['Fields']['Value']:
                                    acro_fields.append(i)
                                return True
                        if acros['Fields']['Value Type'] == 'Indirect Reference':
                            x = __field_check(acros['Fields']['Value'])
                            return x

                if type(acros) == str:
                    if re.search('[0-9]{1,6}\s[0-9]{1,6}\sR', acros):
                        i_obj = acros.replace(' R', '')
                        processed_objects.append(i_obj)
                        i_obj_map = self.__map_object(pdf['Body'], omap, i_obj, None, True)
                        for i in i_obj_map:
                            for j in range(0, len(i_obj_map[i])):
                                if i_obj_map[i][j]['Value']['Value Type'] == 'Array':
                                    if len(i_obj_map[i][j]['Value']['Value']) > 0:
                                        for k in i_obj_map[i][j]['Value']['Value']:
                                            acro_fields.append(k)
                                        return True
                return False


            def __field_actions(acros):
                acro_actions = {}
                if type(acros) == list:
                    for i in acros:
                        acro_fields = __field_actions(i)

                if type(acros) == dict:
                    if acros.has_key('Value Type'):
                        if acros['Value Type'] == 'Indirect Reference':
                            acro_ref = acros['Value'].replace(' R', '')
                            acro_val = self.__map_object(pdf['Body'], omap, acro_ref, None, True)
                            for i in acro_val:
                                for j in range(0, len(acro_val[i])):
                                    if type(acro_val[i][j]['Value']) == dict:
                                        af_val = __field_actions(acro_val[i][j]['Value']['Value'])
                                        if not len(af_val) == 0:
                                            if af_val.has_key('AA'):
                                                aa['acro_adds'].append({acro_ref: af_val['AA']})
                                            else:
                                                acro_actions[acro_ref] = af_val
                        if acros['Value Type'] == 'Dictionary':
                            if acros.has_key('Value'):
                                acro_actions = __field_actions(acros['Value'])
                    if acros.has_key('A'):
                        if acros['A']['Value Type'] == 'Indirect Reference':
                            a_ref = acros['A']['Value'].replace(' R', '')
                            a_val = self.__map_object(pdf['Body'], omap, a_ref, None, True)
                            for i in a_val:
                                for j in range(0, len(a_val[i])):
                                    if type(a_val[i][j]['Value']) == dict:
                                        act_val = __field_actions(a_val[i][j]['Value'])
                                        acro_actions[a_ref] = act_val
                    if acros.has_key('AA'):
                        acts = __form_additional_actions(acros['AA']['Value'])
                        return {'AA': acts}
                    if acros.has_key('S'):
                        if acros['S']['Value Type'] == 'Indirect Reference':
                            s_ref = acros['S']['Value'].replace(' R', '')
                            s_val = self.__map_object(pdf['Body'], omap, s_ref, None, True)
                            for i in s_val:
                                for j in range(0, len(s_val[i])):
                                    if type(s_val[i][j]['Value']) == dict:
                                        s_type = __field_actions(s_val[i][j]['Value'])
                        if acros['S']['Value Type'] == 'Named Object':
                            if acros['S']['Value'] == 'JavaScript':
                                if acros['JS']['Value Type'] == 'Indirect Reference':
                                    js.append(acros['JS']['Value'])
                                    js_ref = acros['JS']['Value'].replace(' R', '')
                                    acro_actions['JavaScript'] = js_ref
                                if acros['JS']['Value Type'] == 'Literal String':
                                    if len(acros['JS']['Value']) > 30:
                                        js_str = str(acros['JS']['Value'][0:30]) + ' Truncated...'
                                        js.append(js_str)
                                        acro_actions['JavaScript'] = js_str
                                    else:
                                        js_str = acros['JS']['Value']
                                        js.append(js_str)
                                        acro_actions['JavaScript'] = js_str
                            if acros['S']['Value'] == 'SubmitForm':
                                exec_key = acros['F']['Value']['F']['Value']
                                return {'SubmitForm': exec_key}
                return acro_actions

            # Check if we even have fields before doing anything else...
            acro_fields = []
            has_fields = __field_check(acros)
            if has_fields:
                for i in acro_fields:
                    x = __field_actions(i)
                    if not len(x) == 0:
                        a_actions.append(x)
            return


        def __process_names(names):
            def __process_named_item(obj):
                if type(obj) == dict:
                    if obj.has_key('Value Type'):
                        if obj['Value Type'] == 'Indirect Reference':
                            embedded_obj = obj['Value'].replace(' R', '')
                            ref_embedded = self.__map_object(pdf['Body'], omap, embedded_obj, None, True)
                            for j in ref_embedded:
                                for k in range(0, len(ref_embedded[j])):
                                    __process_named_item(ref_embedded[j][k])
                        if obj['Value Type'] == 'Dictionary':
                            __process_named_item(obj['Value'])
                    else:
                        if obj.has_key('Names'):
                            if obj['Names'].has_key('Value Type'):
                                if obj['Names']['Value Type'] == 'Array':
                                    for i in range(0, len(obj['Names']['Value'])):
                                        if obj['Names']['Value'][i]['Value Type'] == 'Dictionary':
                                            if obj['Names']['Value'][i]['Value'].has_key('Type'):
                                                if obj['Names']['Value'][i]['Value']['Type']['Value'] == 'Filespec':
                                                    if obj['Names']['Value'][i]['Value'].has_key('F'):
                                                        tmp_var['FileName'] = obj['Names']['Value'][i]['Value']['F']['Value']
                                                        tmp_item.append(tmp_var)
                                                    else:
                                                        if obj['Names']['Value'][i]['Value'].has_key('UF'):
                                                            tmp_var['FileName'] = obj['Names']['Value'][i]['Value']['UF']['Value']
                                                            tmp_item.append(tmp_var)
                                                        else:
                                                            if obj['Names']['Value'][i]['Value'].has_key('EF'):
                                                                tmp_var['Location'] = obj['Names']['Value'][i]['Value']['EF']['Value']
                                                                tmp_item.append(tmp_var)
                                        if obj['Names']['Value'][i]['Value Type'] == 'Literal String':
                                            tmp_var = {}
                                            tmp_var['Name'] = obj['Names']['Value'][i]['Value']
                                        if obj['Names']['Value'][i]['Value Type'] == 'Indirect Reference':
                                            tmp_var['Location'] = obj['Names']['Value'][i]['Value']
                                            tmp_item.append(tmp_var)
                        else:
                            if obj.has_key('Value'):
                                __process_named_item(obj['Value'])
                return


            if type(names) == list:
                for i in names:
                    __process_names(i)

            if type(names) == dict:
                if names.has_key('Value Type'):
                    if names['Value Type'] == 'Indirect Reference':
                        names_ref = names['Value'].replace(' R', '')
                        names_val = self.__map_object(pdf['Body'], omap, names_ref, None, True)
                        for i in names_val:
                            for j in range(0, len(names_val[i])):
                                __process_names(names_val[i][j]['Value'])
                    else:
                        __process_names(names['Value'])
                if names.has_key('JavaScript'):
                    tmp_item = []
                    __process_named_item(names['JavaScript'])
                    for i in tmp_item:
                        name_javascript.append(i)
                if names.has_key('EmbeddedFiles'):
                    tmp_item = []
                    __process_named_item(names['EmbeddedFiles'])
                    for i in tmp_item:
                        name_files.append(i)

            return


        def __process_launch(obj):
            if obj.has_key('Win'): # 'F' key is mandatory
                if obj['Win']['Value'].has_key('F'):
                    if obj['Win']['Value']['F'].has_key('Value Type'):
                        if obj['Win']['Value']['F']['Value Type'] == 'Literal String':
                            win_app = obj['Win']['Value']['F']['Value']
                            launchie.append({'Win Exec': win_app})
            #if obj.has_key('Mac'):
            #    print 'Mac execution object'
            #if obj.has_key('Unix'):
            #    print 'Unix / Linux execution object'
            return


        def __process_js(obj):
            if type(obj) == list:
                for i in range(0, len(obj)):
                    __process_js(obj[i])
            if type(obj) == dict:
                if obj.has_key('Value Type'):
                    __process_js(obj['Value'])
                if obj.has_key('JS'):
                    if obj['JS']['Value Type'] == 'Literal String':
                        js.append(obj['JS']['Value'])
                    if obj['JS']['Value Type'] == 'Indirect Reference':
                        js.append(obj['JS']['Value'])
                        loc = obj['JS']['Value'].replace(' R', '')
                        if not loc in processed_objects:
                            processed_objects.append(loc)
                            loc_map = self.__map_object(pdf['Body'], omap, loc, None, True)
                            for j in loc_map:
                                for k in range(0, len(loc_map[j])):
                                    loc_val = loc_map[j][k]['Value']
                                    __process_js(loc_val)
                if obj.has_key('Name') and obj.has_key('Location'): # We are dealing with a name tree entry
                    # Location is an indirect object reference
                    loc = obj['Location'].replace(' R', '')
                    if not loc in processed_objects:
                        processed_objects.append(loc)
                        loc_map = self.__map_object(pdf['Body'], omap, loc, None, True)
                        for j in loc_map:
                            for k in range(0, len(loc_map[j])):
                                loc_val = loc_map[j][k]['Value']
                                __process_js(loc_val)
                if obj.has_key('S'): # Looks like we're dealing with some other kind of action
                    action = obj['S']['Value']
                    if action == 'Launch': # Check for Win, Mac, or Unix
                        __process_launch(obj)

            if type(obj) == str: # Probably an indirect object. regex it...
                if re.search('[0-9]{1,6}\s[0-9]{1,6}\sR', obj):
                    i_obj = obj.replace(' R', '')
                    processed_objects.append(i_obj)
                    i_obj_map = self.__map_object(pdf['Body'], omap, i_obj, None, True)
                    for j in i_obj_map:
                        for k in range(0, len(i_obj_map[j])):
                            i_obj_val = i_obj_map[j][k]['Value']
                            __process_js(i_obj_val)

            return


        def __validate_xref():
            if omap.has_key('XRT Offsets'):
                for i in omap['XRT Offsets']:
                    tmpo = str(i)
                    if not tmpo in pdf['Body']['Start XRef Entries']:
                        #self.__error_control('SpecViolation', 'Table offset is misaligned.', 'XRef Table')
                        self.__update_mal_index(1, 5)

            if pdf['Body'].has_key('XRef Tables'):
                for i in range(0, len(pdf['Body']['XRef Tables'])):
                    for j in range(1, len(pdf['Body']['XRef Tables'][i])):
                        for k in pdf['Body']['XRef Tables'][i][j]:
                            entry = k.split(' ')
                            if entry[2] == 'n':
                                oentry = int(entry[0])
                                if not omap['IO Offsets'].has_key(oentry):
                                    #self.__error_control('SpecViolation', 'There is no indirect object located at ' + str(oentry), 'XRef Table')
                                    self.__update_mal_index(1, 5)

            # It MIGHT be legal to redefine XRef Streams without any kind of updating like we see with XRef Tables
            # Ignoring this code for now. If I find it's not leegal... I will turn this back on.
            # Example: Download this from VirusTotal: 1E51C658D922410306F042FB12FFEB9F
            # Linearized PDF's may also be a problem for this code :/
            # I might have fixed it. Uncommenting...
            if omap.has_key('XRS Offsets'):
                for i in omap['XRS Offsets']:
                    tmpo = str(i)
                    if not tmpo in pdf['Body']['Start XRef Entries']:
                        #self.__error_control('SpecViolation', 'Table offset is misaligned.', 'XRef Stream')
                        self.__update_mal_index(1, 5)

            # It is highly unlikely that tampering has resulted in the offsets being wrong inside a compressed object
            # stream so, here we check only for the offsets of "uncompressed" 'Used Objects'
            if pdf['Body'].has_key('XRef Streams'):
                for i in range(0, len(pdf['Body']['XRef Streams'])):
                    for j in range(0, len(pdf['Body']['XRef Streams'][i])):
                        if pdf['Body']['XRef Streams'][i][j].has_key('Type'):
                            if pdf['Body']['XRef Streams'][i][j]['Type'] == 'Used Object':
                                entry = pdf['Body']['XRef Streams'][i][j]['Value'].split(' ')
                                oentry = int(entry[0])
                                if not omap['IO Offsets'].has_key(oentry):
                                    #self.__error_control('SpecViolation', 'There is no indirect object located at ' + str(oentry), 'XRef Stream')
                                    self.__update_mal_index(1, 5)

            return


        __validate_xref()
        root_objects, xref_offsets = __find_root()

        js = []

        # Additional Action storage
        aa = {}
        aa['cat_adds'] = []
        aa['acro_adds'] = []
        aa['page_adds'] = []
        aa['annot_adds'] = []

        try:
            #pages, names, outlines, openactions, acroforms, uris, cat_a = __get_catalog_data()
            pages, names, outlines, openactions, acroforms, uris = __get_catalog_data()
        except Exception as e:
            raise e
        page_count = __get_pagecount()
        acro_count = len(acroforms)
        open_count = len(openactions)

        a_actions = []
        if acro_count > 0:
            __process_acroforms(acroforms)

        if page_count > 0: # Umm it better be...
            __process_pages(pages)
        else:
            self.__error_control('SpecViolation', 'Unable to locate a page count during summarization')

        name_files, name_javascript = [], []
        if len(names) > 0:
            __process_names(names)

        js_checklist = (
            openactions,
            name_javascript
        )
        launchie = []
        for i in js_checklist:
            __process_js(i)
        js_count = len(js)

        ad = []
        if pdf['Body'].has_key('Arbitrary Data'):
            for i in pdf['Body']['Arbitrary Data']:
                ad.append({'Length': i['Length'], 'Type': i['Value Type'], 'Offset': i['Offset']})
        summary['Encryption'] = {}
        if self.__is_crypted:
            summary['Encryption']['enabled'] = True
            summary['Encryption']['file_key'] = self.__crypt_handler_info['file_key'].encode('hex').upper()
            summary['Encryption']['key_length'] = self.__crypt_handler_info['key_length']
            if self.__crypt_handler_info['method'] == 'V2' or self.__crypt_handler_info['method'] == 'RC4':
                summary['Encryption']['algorithm'] = 'RC4'
            if self.__crypt_handler_info['method'][0:3] == 'AES':
                summary['Encryption']['algorithm'] = 'AES'

        else:
            summary['Encryption']['enabled'] = False
        summary['Additional Actions'] = aa
        summary['Arbitrary Data'] = ad
        summary['Pages'] = page_count
        summary['AcroForms'] = acro_count
        summary['AcroForm Actions'] = a_actions
        summary['OpenActions'] = open_count
        summary['Names'] = names
        summary['EmbeddedFiles'] = name_files
        summary['JavaScript'] = name_javascript
        summary['JS'] = js_count
        summary['Launch'] = launchie
        if pdf['Body'].has_key('Object Streams'):
            summary['Object Streams'] = len(pdf['Body']['Object Streams'])
        else:
            summary['Object Streams'] = 0

        return summary


    def __map_object(self, pdf, omap, ref = None, offset = None, trace = False):
        ret_val = {}
        ret_val['Indirect Objects'] = []
        ret_val['Object Streams'] = []

        if not ref == None:
            if omap['IO'].has_key(ref):
                for i in omap['IO'][ref]:
                    ret_val['Indirect Objects'].append({'Index': i[0]})
            if omap['OS'].has_key(ref):
                for i in omap['OS'][ref]:
                    ret_val['Object Streams'].append({'Index': i[0]})

        if trace:
            # Return values instead of just the index of where something is located
            for i in ret_val:
                for j in range(0, len(ret_val[i])):
                    index = ret_val[i][j]['Index']
                    ret_val[i][j]['Value'] = pdf[i][index][ref]
        return ret_val


    def __assemble_map(self, pdf, omap):
        # Process Indirect Objects:
        for i in range(0, len(pdf['Indirect Objects'])):
            key = pdf['Indirect Objects'][i].keys()[0] # For indirect objects, there should only ever be one key per index
            if not omap['IO'].has_key(key):
                omap['IO'][key] = []
            omap['IO'][key].append([i, pdf['Indirect Objects'][i][key]['Offset']])
            # Reverse map of offsets to indirect objects
            if not omap['IO Offsets'].has_key(pdf['Indirect Objects'][i][key]['Offset']):
                omap['IO Offsets'][pdf['Indirect Objects'][i][key]['Offset']] = ''
            omap['IO Offsets'][pdf['Indirect Objects'][i][key]['Offset']] = key

        # Process object streams
        if pdf.has_key('Object Streams'):
            for i in range(0, len(pdf['Object Streams'])):
                keys = pdf['Object Streams'][i].keys()
                for key in keys:
                    if not key == 'Back Ref':
                        if not omap['OS'].has_key(key):
                            omap['OS'][key] = []
                        back_ref = pdf['Object Streams'][i]['Back Ref']
                        src_index = omap['IO'][back_ref]
                        omap['OS'][key].append([i, back_ref, src_index])

        # Process xref table offsets (just the table offsets, not the offsets of all the objects within)
        if pdf.has_key('XRef Tables'):
            for i in range(0, len(pdf['XRef Tables'])):
                omap['XRT Offsets'].append(pdf['XRef Tables'][i][0]['Offset'])

        if pdf.has_key('XRef Streams'):
            for i in range(0, len(pdf['XRef Streams'])):
                backref = pdf['XRef Streams'][i][-1:][0]['Back Ref']
                if omap['IO'].has_key(backref):
                    omap['XRS Offsets'].append(omap['IO'][backref][0][1])
        return


    def __exception2str(self, exception):
        e = {}
        for i in exception:
            if type(i) == Exception:
                e['Exception'] = i.message
        return e


    def __process_streams(self, x, bod, summary):
        stream_displays = {
            'ttf': self.show_ttf,
            'bitmap': self.show_bitmaps,
            'graphic': self.show_pics,
            'olecf': self.show_embedded_files,
            'docx': self.show_embedded_files,
            'xlsx': self.show_embedded_files,
            'zip': self.show_embedded_files,
            'arbitrary': self.show_arbitrary,
            'pdf_mcid': self.show_text,
            'pefile': False,
            'Unknown': True
        }
        decoded_streams = [
            'XRef',
            'ObjStm'
        ]
        cur_stream = ''
        i_object_index = 0
        for i in bod['Indirect Objects']:
            cur_error = ''
            obj_name = i.keys()[0]
            if i[obj_name].has_key('Stream Dimensions'):
                stream_start = i[obj_name]['Stream Dimensions']['Start']
                if i[obj_name]['Stream Dimensions']['Length']['Value Type'] == 'Unknown':
                    stream_length = int(i[obj_name]['Stream Dimensions']['Length']['Value'])
                if i[obj_name]['Stream Dimensions']['Length']['Value Type'] == 'Indirect Reference':
                    # Go grab object specified in indirect reference
                    i_ref =  i[obj_name]['Stream Dimensions']['Length']['Value']
                    i_ref = i_ref.replace(' R', '')
                    for ii in range(0, len(bod['Indirect Objects'])):
                        if bod['Indirect Objects'][ii].has_key(i_ref):
                            stream_length = int(bod['Indirect Objects'][ii][i_ref]['Value'])
                            break

                cur_stream = x[stream_start:stream_start + stream_length]
                # We got the stream. Decode it. Get decoding parameters if the exist
                if i[obj_name]['Value'].has_key('Filter'):
                    filter = i[obj_name]['Value']['Filter']['Value']
                else:
                    filter = None
                if i[obj_name]['Value'].has_key('DecodeParms'):
                    decodeparms = i[obj_name]['Value']['DecodeParms']['Value']
                else:
                    decodeparms = None

                # Setup our filters for processing...
                if filter == None:
                    filter = []
                if type(filter) == list:
                    len_filter = len(filter)
                else:
                    len_filter = 1
                    filter = [filter]

                if decodeparms == None:
                    decodeparms = []
                if type(decodeparms) == list:
                    len_decodeparms = len(decodeparms)
                if type(decodeparms) == dict:
                    len_decodeparms = 1
                    decodeparms = [decodeparms]

                # The above setup of filters and decodeparms ensures we have a 1 to 1 relation betwenn the two
                # and it always results in 2 arrays.

                # Gotta parse'em all!
                cur_filter = ''
                cur_decoder = ''
                if len_filter > 0:
                    for j in range(0, len_filter):
                        cur_filter = filter[j]
                        if len_decodeparms > 0:
                            cur_decoder = decodeparms[j]
                        else:
                            cur_decoder = ''
                        # Send to decoder now...
                        try:
                            if i[obj_name]['Value'].has_key('Type'):
                                if not i[obj_name]['Value']['Type']['Value'] == 'XRef':
                                    cur_stream = self.__filter_parse(cur_stream, cur_filter, cur_decoder, obj_name)
                                else:
                                    cur_stream = self.__filter_parse(cur_stream, cur_filter, cur_decoder, 'NO_DECRYPT')
                            else:
                                cur_stream = self.__filter_parse(cur_stream, cur_filter, cur_decoder, obj_name)
                        except SpecViolation as e:
                            self.__error_control(e.__repr__(), e.message, obj_name)
                        except Exception as e:
                            cur_error = 'Exception:', type(e), e, obj_name
                else:
                    if self.__is_crypted:
                        if not obj_name in self.__crypt_handler_info['o_ignore']:
                            cur_stream = self.crypto.decrypt(self.__crypt_handler_info, cur_stream, 'stream', obj_name)

                if not cur_error == '':
                    bod['Indirect Objects'][i_object_index][obj_name]['Stream Error'] = self.__exception2str(cur_error)
                    i_object_index += 1
                    continue
                stream_type = None
                if i[obj_name]['Value'].has_key('Type'):
                    if i[obj_name]['Value']['Type']['Value'] == 'XRef':
                        stream_type = 'XRef'
                        bod['Indirect Objects'][i_object_index][obj_name]['Stream Type'] = 'XRef'
                        try:
                            xref_stream = self.__process_xref_stream(cur_stream, i[obj_name]['Value'], obj_name)
                        except:
                            cur_error = 'exception:(__process_xref_stream) in %s' % obj_name
                        if not cur_error == '':
                            bod['Indirect Objects'][i_object_index][obj_name]['Stream Error'] = self.__exception2str(cur_error)
                            i_object_index += 1
                            continue
                        if not bod.has_key('XRef Streams'):
                            bod['XRef Streams'] = []
                        bod['XRef Streams'].append(xref_stream)
                        xref_index = len(bod['XRef Streams']) - 1
                        bod['Indirect Objects'][i_object_index][obj_name]['XRef Stream Index'] = xref_index
                        bod['Indirect Objects'][i_object_index][obj_name].pop('Stream Dimensions')
                    if i[obj_name]['Value']['Type']['Value'] == 'ObjStm':
                        stream_type = 'ObjStm'
                        bod['Indirect Objects'][i_object_index][obj_name]['Stream Type'] = 'ObjStm'
                        try:
                            objstm = self.__process_object_stream(cur_stream, i[obj_name]['Value'], obj_name)
                        except:
                            cur_error = 'exception:(__process_object_stream) in %s' % obj_name
                        if not cur_error == '':
                            bod['Indirect Objects'][i_object_index][obj_name]['Stream Error'] = self.__exception2str(cur_error)
                            i_object_index += 1
                            continue
                        if not bod.has_key('Object Streams'):
                            bod['Object Streams'] = []
                        bod['Object Streams'].append(objstm)
                        objstm_index = len(bod['Object Streams']) - 1
                        bod['Indirect Objects'][i_object_index][obj_name]['Object Stream Index'] = objstm_index
                        bod['Indirect Objects'][i_object_index][obj_name].pop('Stream Dimensions')
                if stream_type == None:
                    stream_type = self.__identify_stream(cur_stream)
                    if stream_type == '':
                        stream_type = 'Unknown'
                    if stream_type == 'pdf_mcid':
                        try:
                            cur_stream = self.__parse_mcid(cur_stream)
                        except:
                            pass
                stream_hash = self.__hash_stream(cur_stream)
                bod['Indirect Objects'][i_object_index][obj_name]['Stream Hashes'] = stream_hash
                if self.dump_streams:
                    dump_file = self.__gen_random_file()
                    open(self.dump_loc + dump_file, 'wb').write(cur_stream)
                    bod['Indirect Objects'][i_object_index][obj_name]['Stream Dump Location'] = self.dump_loc + dump_file
                    summary['Dumped Files'].append(self.dump_loc + dump_file)
                if not stream_type in decoded_streams:
                    if stream_displays[stream_type]:
                        bod['Indirect Objects'][i_object_index][obj_name]['Stream Data'] = cur_stream

                if i[obj_name]['Value'].has_key('Type') and stream_type == 'Unknown':
                    stream_type = bod['Indirect Objects'][i_object_index][obj_name]['Value']['Type']['Value']
                bod['Indirect Objects'][i_object_index][obj_name]['Stream Type'] = stream_type

                # Last thing to do...
                if bod['Indirect Objects'][i_object_index][obj_name].has_key('Stream Dimensions'):
                    bod['Indirect Objects'][i_object_index][obj_name].pop('Stream Dimensions')
            i_object_index += 1
        return bod


    def __parse_mcid(self, my_stream):
        def get_strings(x):
            strings = []
            t_pos = 0
            b_pos = t_pos
            temp_str = x[t_pos:]
            top_str = x
            last_offset = 0
            last_length = 0

            c = 0  # Counter to keep track of nesting. When this reaches zero, we're done

            while True:
                if re.search('\(', top_str):
                    s_start = re.search('\(', top_str).start()
                    # Make sure it's not escaped.
                    es_start = re.search('\\\\\(', top_str[s_start - 1:s_start + 1])
                    if es_start == None: # We have an open parentheses thats not escaped. Begin literal string!
                        strings.append({'Offset': s_start + last_offset + last_length, 'Length': ''})
                        last_offset = last_offset + s_start
                        l_strings = len(strings)
                        temp_str = temp_str[s_start + 1:]
                        b_pos += s_start + 1
                        c += 1
                        while True:
                            try:
                                boundary = re.search('\(|\)', top_str[b_pos:]).start()
                            except:
                                return 'Error: (Fatal: Malformed literal string.)'
                            b_pos += boundary
                            seq = top_str[b_pos:b_pos + 1]
                            if seq == ')' and re.search('\\\\\)', top_str[b_pos - 1:b_pos + 1]) == None:
                                b_pos += 1
                                c -= 1
                            if seq == ')' and not re.search('\\\\\)', top_str[b_pos - 1:b_pos + 1]) == None:
                                b_pos += 1
                            if seq == '(' and re.search('\\\\\(', top_str[b_pos - 1:b_pos + 1]) == None:
                                b_pos += 1
                                c += 1
                            if seq == '(' and not re.search('\\\\\(', top_str[b_pos - 1:b_pos + 1]) == None:
                                b_pos += 1
                            new_str = (top_str[s_start:b_pos])
                            temp_str = temp_str[boundary + 1:]
                            if c == 0:
                                length = len(new_str)
                                end = strings[l_strings - 1]['Offset'] + (length - 1)
                                strings[l_strings - 1]['Length'] = length
                                strings[l_strings - 1]['End'] = end
                                last_length = last_length + len(new_str)
                                top_str = temp_str
                                b_pos = 0
                                break
                else:
                    break
            return strings


        def parse_map(map, f):
            data = ''
            for i in map:
                data += f[i['Offset'] + 1: i['End']].replace('\(', '(').replace('\)', ')')
            return data


        string_map = get_strings(my_stream)
        data = parse_map(string_map, my_stream)
        return data


    def __hash_stream(self, my_stream):
        stream_hash = {}
        stream_hash['MD5'] = hashlib.md5(my_stream).hexdigest().upper()
        stream_hash['SHA1'] = hashlib.sha1(my_stream).hexdigest().upper()
        stream_hash['SHA256'] = hashlib.sha256(my_stream).hexdigest().upper()
        return stream_hash


    def __identify_stream(self, my_stream):
        stream_type = ''
        l_stream = len(my_stream)

        if re.match('\x00\x01\x00\x00', my_stream[0:4]) and \
                re.match('(cmap|glyf|head|hhea|hmtx|loca|maxp|name|post|OS/2|GSUB|GPOS|BASE|JSTF|GDEF|cvt |'
                     'DSIG|EBDT|EBLC|EBSC|fpgm|gasp|hdmx|kern|LTSH|prep|PCLT|VDMX|vhea|vmtx)', my_stream[12:16]):
            stream_type = 'ttf'
            return stream_type

        if (
            re.search('BT', my_stream[0: 200]) and
            re.search('ET', my_stream) and (
                re.search('TJ', my_stream) or
                re.search('Tj', my_stream)
            ) and (
                re.search('Tm', my_stream) or
                re.search('Td', my_stream) or
                re.search('TD', my_stream)
            ) and
                re.search('\[\(', my_stream) and
                re.search('\)\]', my_stream)
        ):
            stream_type = 'pdf_mcid'
            return stream_type

        if re.match('\x4D\x5A', my_stream[0:2]):
            if len(my_stream) > 64:
                ntoffset = struct.unpack('<i', my_stream[60:64])[0]
                if len(my_stream) > (ntoffset + 2):
                    if re.match('\x50\x45', my_stream[ntoffset:ntoffset + 2]):
                        stream_type = 'pefile'
                        return stream_type

        if re.match('\xFF\xD8\xFF', my_stream[0:3]) and \
                re.match('\xFF\xD9$', my_stream[l_stream - 2:l_stream]):
            stream_type = 'graphic'

        if re.match('\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', my_stream[0:8]):
            stream_type = 'olecf'

        if re.match('\x50\x4b\x03\x04', my_stream[0:4]):
            stream_type = 'zip'

        if stream_type == 'zip' and re.search('xl/_rels', my_stream[4:]):
            stream_type = 'xlsx'

        if stream_type == 'zip' and re.search('word/_rels', my_stream[4:]):
            stream_type = 'docx'

        return stream_type


    def __filter_parse(self, my_stream, filter, decodeparms, cur_obj):
        ignore_filters = {
            'DCTDecode',
            'DCT',
            'CCITTFaxDecode',
            'CCF'
        }
        known_encoders = {
            'FlateDecode',
            'Fl',
            'LZWDecode',
            'LZW',
            'ASCIIHexDecode',
            'AHx',
            'ASCII85Decode',
            'A85',
            'Crypt'
        }
        known_not_implemented = {
            'RunLengthDecode',
            'RL',
            'JBIG2Decode',
            'JPXDecode'
        }

        if self.__is_crypted:
            if not cur_obj in self.__crypt_handler_info['o_ignore']:
                if filter == 'Crypt':
                    if decodeparms == '':
                        # Assume crypt filer name = 'Identity' and skip decryption
                        return my_stream
                    else:
                        # Assume crypt filer name = 'StdCF' and decrypt
                        my_stream = self.crypto.decrypt(self.__crypt_handler_info, my_stream, 'stream', cur_obj, 'StdCF')
                else:
                    my_stream = self.crypto.decrypt(self.__crypt_handler_info, my_stream, 'stream', cur_obj)

        new_stream = my_stream

        if re.search('[0-9]{1,6}\s[0-9]{1,6}\sR', filter):
            return new_stream

        if filter not in ignore_filters:
            if filter in known_not_implemented:
                return new_stream
            if filter in known_encoders:
                if filter == 'FlateDecode' or filter == 'Fl':
                    new_stream = self.__flatedecode(new_stream)
                if filter == 'LZWDecode' or filter == 'LZW':
                    new_stream = self.__lzw_decode(new_stream)
                if filter == 'ASCIIHexDecode' or filter == 'AHx':
                    new_stream = self.__asciihexdecode(new_stream)
                if filter == 'ASCII85Decode' or filter == 'A85':
                    new_stream = self.__ascii85_decode(new_stream)
            else:
                raise SpecViolation("Invalid filter type passed to /Filter" + ': \"' + filter + '\" ')
        else:
            return new_stream

        if not decodeparms == '':
            if type(decodeparms) == dict:
                if decodeparms.has_key('Predictor'):
                    if decodeparms['Predictor'] == 1:
                        return new_stream
                    if decodeparms['Predictor'] == 2:
                        new_stream = self.__decoder_tiff(new_stream)
                    if decodeparms['Predictor'] > 2:
                        # PNG decoding detected
                        new_stream = self.__decoder_png(new_stream, decodeparms)

        return new_stream


    def __process_xref_stream(self, obj_stream, values, bacRef):
        def data_parse(data, W_array):
            pos = 0

            # Get type
            d_type = data[pos:W_array[0]]
            len_d_type = len(d_type)
            pos += W_array[0]
            x = 0
            for i in range(0, len_d_type):
                x += ord(d_type[i]) * (256 ** (len_d_type - (i + 1)))
            d_type = x

            # Get object data
            o_data = data[pos:pos + W_array[1]]
            len_o_data = len(o_data)
            pos += W_array[1]
            x = 0
            for i in range(0, len_o_data):
                x += ord(o_data[i]) * (256 ** (len_o_data - (i + 1)))
            o_data = x

            # Get generation or index number
            gi_num = data[pos:pos + W_array[2]]
            len_gi_num = len(gi_num)
            x = 0
            for i in range(0, len_gi_num):
                x += ord(gi_num[i]) * (256 ** (len_gi_num - (i + 1)))
            gi_num = x
            # Decisions... decisions...
            if d_type == 0: # We got a legacy xref style entry. (ex: 0000000000 65535 f)
                x = {'Type': 'Free Object', 'Value': str(o_data).zfill(10) + ' ' + str(gi_num).zfill(5) + ' f'}
                return x

            if d_type == 1:
                x = {'Type': 'Used Object', 'Value': str(o_data).zfill(10) + ' ' + str(gi_num).zfill(5) + ' n'}
                return x

            if d_type == 2:
                x = {'Type': 'Compressed Object', 'Value': { 'Object Stream Number': o_data, 'Object Index': gi_num}}
                return x

            raise Exception('__process_xref_stream() -> data_parse() Fatal: Invalid data type in XRef stream. Exiting.')

        len_obj_stream = len(obj_stream)
        field_count = len(values['W']['Value'])
        wfield_1, wfield_2, wfield_3 = '', '', ''
        if not field_count == 3:
            raise Exception('XRef stream doesn\'t specify enough fields!')
        loop_count = 0
        while True:
            if loop_count == 0:
                wfield_1 = int(values['W']['Value'][0]['Value'])
                if wfield_1 == 0:
                    raise Exception('__process_xref_stream) Field 1 = 0.')
            if loop_count == 1:
                wfield_2 = int(values['W']['Value'][1]['Value'])
                if wfield_2 == 0:
                    raise Exception('__process_xref_stream) Field 2 = 0.')
            if loop_count == 2:
                wfield_3 = int(values['W']['Value'][2]['Value'])
                if wfield_2 == 0:
                    raise Exception('__process_xref_stream) Field 3 = 0.')
            loop_count += 1
            if loop_count > field_count:
                break
        if wfield_1 == '' or wfield_2 == '' or wfield_3 == '':
            raise Exception('Something happened parsing XRef stream fields.')

        field_width = wfield_1 + wfield_2 + wfield_3

        f_width_array = [
            wfield_1,
            wfield_2,
            wfield_3
        ]

        xref_tbl = []
        pos = 0
        while True:
            tmp_data = obj_stream[pos:pos + field_width]
            tmp_xref_data = data_parse(tmp_data,f_width_array)
            xref_tbl.append(tmp_xref_data)
            pos += field_width
            if pos >= len_obj_stream:
                break
        xref_tbl.append({'Back Ref': bacRef})
        return xref_tbl


    def __process_object_stream(self, obj_stream, values, backRef):
        obj_str = []
        num_objects = int(values['N']['Value'])
        first_pos = int(values['First']['Value'])
        pos = 0
        objects = obj_stream[first_pos:]
        table = obj_stream[:first_pos]
        while True:
            if re.match('(\x0D|\x0A|\x09|\x20)', table):
                table = table[1:]
                continue
            if re.match('(\x0D|\x0A|\x09|\x20)', table[-1:]):
                table = table[:-1]
                continue
            break
        for i in range(0, num_objects):
            obj = re.match('\d{1,8} \d{1,8}',table[pos:]).group()
            obj_num = re.match('\d{1,8}', obj).group()
            obj_offset = re.match('\d{1,8}', obj[len(obj_num) + 1:]).group()
            tmp_dict = {}
            tmp_dict['Indirect Object'] = obj_num + ' 0'
            tmp_dict['Offset'] = int(obj_offset)
            tmp_dict['Index'] = i
            obj_str.append(tmp_dict)
            pos += len(obj) + 1
        new_obj_stream = sorted(obj_str, key=lambda k: k['Offset'])
        final_obj_stream = {}
        final_obj_stream['Indirect Objects'] = {}
        final_obj_stream['Indirect Objects']['Back Ref'] = backRef
        for i in range(0, len(new_obj_stream)):
            curr_i_object = new_obj_stream[i]['Indirect Object']
            if i < (len(new_obj_stream) - 1):
                curr_obj = objects[new_obj_stream[i]['Offset']:new_obj_stream[i + 1]['Offset']]
            else: # Last entry
                curr_obj = objects[new_obj_stream[i]['Offset']:]
            curr_obj += ' endobj'
            i_obj_data = self.__i_object_def_parse(curr_obj, 0, 'objstm', 'NO_DECRYPT')
            final_obj_stream['Indirect Objects'][curr_i_object] = {}
            if not i_obj_data[0] == '':
                final_obj_stream['Indirect Objects'][curr_i_object]['Value'] = i_obj_data[0]['Value']
                final_obj_stream['Indirect Objects'][curr_i_object]['Value Type'] = i_obj_data[0]['Value Type']
            else:
                final_obj_stream['Indirect Objects'][curr_i_object]['Value'] = None
                final_obj_stream['Indirect Objects'][curr_i_object]['Value Type'] = None
            final_obj_stream['Indirect Objects'][curr_i_object]['Offset'] = new_obj_stream[i]['Offset']
            final_obj_stream['Indirect Objects'][curr_i_object]['Index'] = new_obj_stream[i]['Index']
        return final_obj_stream['Indirect Objects']


    def __free_base(self, src, sc, dc):
        src_base = len(sc)
        dst_base = len(dc)
        len_src = len(src)
        sv = 0

        # Need value of input before we can begin conversion
        for i in range(0, len_src):
            multiplier = sc.index(src[i])
            power = len_src - i - 1
            sv += (src_base ** power) * multiplier
        # sv contains decimal (base 10) version of the input

        # Begin conversion
        if sv == 0:
            return dc[0]
        dv = ''
        while True:
            if sv == 0:
                break
            tmp_int = int(sv / dst_base)
            dv = dc[(sv % dst_base)] + dv
            sv = tmp_int

        return dv


    def __ascii85_decode(self, my_stream):
        att = ''
        for i in range(0, 256):
            att += chr(i) # att = all the things! charset containing all 256 chars

        ascii85 = ''
        for i in range(33, 118):
            ascii85 += chr(i) # ascii85 charset

        new_encoded = my_stream.replace('\x00', '')
        new_encoded = new_encoded.replace('\x09', '')
        new_encoded = new_encoded.replace('\x0A', '')
        new_encoded = new_encoded.replace('\x0D', '')
        new_encoded = new_encoded.replace('\x20', '')
        new_encoded = new_encoded.replace('z', '!!!!!')

        try:
            end = re.search('~>', new_encoded).start()
            new_encoded = new_encoded[:end]
        except AttributeError as e:
            raise SpecViolation("ASCII85 stream improperly terminated")

        lex = len(new_encoded) # length of x
        mox = lex % 5 # mod of x
        loops = lex / 5 # main loop count
        dec_str = ''

        if not mox == 0:
            padding = (5 - mox)
        else:
            padding = 0

        if padding > 0:
            loops += 1
            for i in range(0, padding):
                new_encoded += 'u'

        i = 0
        while i < (5 * loops):
            tmp = new_encoded[i:i+5]
            res = self.__free_base(tmp, ascii85, att)
            if len(res) < 4:
                for j in range(0, 4 - len(res)):
                    res = chr(0) + res
            i += 5
            dec_str += res

        if padding > 0 and len(dec_str) > 0:
            for i in range(0, padding):
                dec_str = dec_str[:-1]

        return dec_str


    def __lzw_decode(self, data):
        return ''.join(LZWDecoder(data).run())


    def __asciihexdecode(self, my_stream):
        end = re.search('>', my_stream).start()
        new_stream = my_stream[0:end]
        new_stream = new_stream.replace('\x00', '')
        new_stream = new_stream.replace('\x09', '')
        new_stream = new_stream.replace('\x0A', '')
        new_stream = new_stream.replace('\x0D', '')
        new_stream = new_stream.replace('\x20', '')
        new_stream = new_stream.decode('hex')
        return new_stream


    def __flatedecode(self, i_buffer):
        data = zlib.decompress(i_buffer)

        return data


    def __decoder_tiff(self, my_stream):
        # No decoder for this
        raise Exception('TIFF encoded')
        #return my_stream


    def __decoder_png(self, my_stream, parms):
        def algo_0(s, c):
            return s
        def algo_1(r1):
            decoded_data = r1[0]
            for i in range(1, len(r1)):
                a = ord(decoded_data[-1:])
                b = ord(r1[i])
                decoded_data += chr((a + b) % 256)
            return decoded_data
        def algo_2(r1, r2):
            decoded_data = ''
            for i in range(0, len(r1)):
                a = ord(r1[i])
                b = ord(r2[i])
                decoded_data += chr((a + b) % 256)
            return decoded_data
        def algo_3(s, c):
            return s
        def algo_4(s, c):
            return s
        def algo_5(s, c):
            new_s = ''
            s_pos = c + 1
            b_pos = 0
            rows = len(s) / (c + 1)
            new_s += s[1:s_pos]
            return s


        num_columns = int(parms['Columns']['Value'])
        if parms.has_key('Colors'):
            num_colors = int(parms['Colors']['Value'])
        else:
            num_colors = 1
        row_width = (num_columns * num_colors)
        rows = len(my_stream) / (row_width + 1)
        predictor = ord(my_stream[0])
        row_1_data = my_stream[1:row_width + 1]

        if predictor < 2:
            start_row = 0
            decoded_data = ''
        else:
            start_row = 1
            decoded_data = row_1_data

        for row in range(start_row, rows - 1):
            predictor = ord(my_stream[(row * (row_width + 1))])

            if predictor == 0:
                decoded_data += algo_0(row_1_data, row_width)
            if predictor == 1:
                row_1_data = my_stream[(row * (row_width + 1)) + 1:(row * (row_width + 1)) + (row_width + 1)]
                decoded_data += algo_1(row_1_data)
            if predictor == 2:
                row_1_data = decoded_data[-row_width:]
                row_2_data = my_stream[(row * (row_width + 1)) + 1:(row * (row_width + 1)) + (row_width + 1)]
                decoded_data += algo_2(row_1_data, row_2_data)
            if predictor == 3:
                #decoded_data += algo_3(my_stream, row_width)
                raise Exception('predictor = 3')
            if predictor == 4:
                #decoded_data += algo_4(my_stream, row_width)
                raise Exception('predictor = 4')
            if predictor == 5:
                #decoded_data += algo_5(my_stream, row_width)
                raise Exception('predictor = 5')

        return decoded_data


    def __body_scan(self, x, s_point, summary):
        c = s_point
        l = len(x)
        body = {}

        current_position = -1
        last_position = c
        arb_data = ''
        while True:
            if last_position == current_position:
                # We have an infinite loop in progress if we don't increment by at least 1 here.
                # Probably caused by arbitrary data in the PDF. Might wanna increase the malware index.
                arb_data += x[c]
                if arb_data == '%':
                    # We have a comment in no mans land. Placing comments anywhere... is legal per the spec.
                    # I don't think we can just call this arbitrary data. Skipping past it.
                    end_arb = self.__line_scan(x, c + 1)[1]
                    c = end_arb
                    arb_data = ''
                    last_position = c
                    c += 1
                    current_position = c
                    continue
                if not body.has_key('Arbitrary Data'):
                            body['Arbitrary Data'] = []
                c += 1
                if re.search('(\d{1,10}\s+\d{1,10}\s+obj|xref|trailer|startxref|%%EOF)', x[c:]):
                    end_arb = re.search('(\d{1,10}\s+\d{1,10}\s+obj|xref|trailer|startxref|%%EOF)', x[c:]).start()
                    arb_data += x[c:c + end_arb]
                    c += end_arb
                    arb_type, arb_data = self.__process_arbitrary_data(arb_data)
                    len_arb = len(arb_data)
                    if self.show_arbitrary:
                        body['Arbitrary Data'].append({'Value Type': arb_type,
                                                       'Offset': current_position,
                                                       'Length': len_arb,
                                                       'Value': arb_data})
                    else:
                        body['Arbitrary Data'].append({'Value Type': arb_type,
                                                       'Length': len_arb,
                                                       'Offset': current_position,})
                    if self.dump_streams:
                        dump_file = self.__gen_random_file()
                        open(self.dump_loc + dump_file, 'wb').write(arb_data)
                        body['Arbitrary Data'][-1]['Stream Dump Location'] = self.dump_loc + dump_file
                        summary['Dumped Files'].append(self.dump_loc + dump_file)
                    arb_data = ''
                else:
                    break
            if c >= l:
                break
            last_position = c
            current_position = last_position
            char_loc = self.__eol_scan(x, c)
            if char_loc == l:
                break # We reached the end of the file. Peace out!
            if re.match('\s', x[char_loc]):
                # Got spaces in between objects. Proceede to next position.
                if len(arb_data) > 0:
                    arb_data += x[char_loc]
                c += 1
                current_position = c
                continue
            c = char_loc
            current_position = c
            if re.match('\d{1,10}\s+\d{1,10}\s+obj', x[char_loc:char_loc + 26]):
                # See if we've encountered an indirect object. We probably have.
                if re.search('obj', x[char_loc:]):
                    search_end = re.search('obj', x[char_loc:]).end()
                    temp_indirect_obj = x[char_loc:char_loc + search_end]
                    s_object = self.__i_object_parse(temp_indirect_obj)
                    cur_obj = s_object[1][0].replace(' obj', '')
                    cur_val = {}
                    cur_val['Offset'] = char_loc
                    if s_object[2] > 0:
                        self.__update_mal_index(s_object[2], 7)
                    if self.__is_crypted:
                        self.__crypt_handler_info['o_keys'][cur_obj] = self.crypto.gen_obj_key(self.__crypt_handler_info['file_key'], \
                                                                                               self.__crypt_handler_info['key_length'], \
                                                                                               self.__crypt_handler_info['method'], \
                                                                                               cur_obj)
                    if s_object[0] == 'obj': # We have a valid indirect object
                        c += search_end
                        if not body.has_key('Indirect Objects'):
                            body['Indirect Objects'] = []
                        index = len(body['Indirect Objects'])
                        # Since we have a valid indirect object identifier, parse the indirect object definition.
                        ret = self.__i_object_def_parse(x, c, 'obj', cur_obj)
                        c = ret[1]
                        # Check for obfuscation in named objects!
                        if len(ret[0]) > 0:
                            try:
                                deob_ret = self.__named_object_deobfuscate(ret[0])
                            except Exception as e:
                                self.__error_control(e.__repr__(), e.message,  cur_obj)
                            cur_val['Value Type'] = deob_ret['Value Type']
                            cur_val['Value'] = deob_ret['Value']
                        else:
                            cur_val['Value Type'] = None
                            cur_val['Value'] = ''
                        body['Indirect Objects'].append({cur_obj: cur_val})
                        if type(deob_ret['Value']) == dict:
                            if deob_ret['Value'].has_key('Type'):
                                if deob_ret['Value']['Type']['Value'] == 'XRef':
                                    if deob_ret['Value'].has_key('Prev'):
                                        if not body.has_key('Start XRef Entries'):
                                            body['Start XRef Entries'] = []
                                        body['Start XRef Entries'].append(deob_ret['Value']['Prev']['Value'])
                        del cur_val
                        if re.match('endobj', x[c:]):
                            c += 6
                            current_position = c
                            continue
                        if re.match('stream', x[c:]):
                            stream_dimensions = {}
                            c += 6
                            if body['Indirect Objects'][index][cur_obj]['Value'].has_key('Length'):
                                stream_dimensions['Length'] = body['Indirect Objects'][index][cur_obj]['Value']['Length']
                            else:
                                self.__error_control('SpecViolation', 'Stream dictionary missing /Length', cur_obj)
                            ret = self.__get_stream_dimensions(x, c)
                            c = ret[0]
                            stream_dimensions['Start'] = ret[1]
                            body['Indirect Objects'][index][cur_obj]['Stream Dimensions'] = stream_dimensions

                            try:
                                if re.search('endobj', x[c:]):
                                    c += re.search('endobj', x[c:]).end()
                                    current_position = c
                                    continue
                            except Exception as e:
                                self.__error_control('SpecViolation', 'endobj is missing', cur_obj)

                    else:
                        raise Exception('Invalid object.')
            if re.match('xref', x[char_loc:char_loc + 4]):
                xrf_tbl = []
                xref_offset = char_loc
                xrf_tbl.append({'Offset': xref_offset})
                c += 4
                current_position = c
                while True:
                    char_loc = self.__eol_scan(x, c)
                    # This next line should be 2 digits.
                    # Read it so we know how to parse the xref table.
                    xref_entries = self.__line_scan(x, char_loc)
                    c = xref_entries[1]
                    xref_entries = xref_entries[0].split(' ')
                    # index 0 = The first defined object
                    # index 1 = The number of objects in the table.
                    try:
                        tmp_xrf_tbl = self.__xref_parse(x, xref_entries, c)
                    except SpecViolation as e:
                        self.__error_control(e.__repr__(), e.message, 'xref: offset: ' + str(current_position))
                    except Exception as e:
                        self.__error_control(e.__repr__(), e.message,  'xref: offset: ' + str(current_position))
                    c = tmp_xrf_tbl[1]
                    current_position = c
                    xrf_tbl.append(tmp_xrf_tbl[0])
                    # Check if we got more xref stuff or if we are at the trailer
                    tmp_char_loc = self.__eol_scan(x, c)
                    tmp_perm_str = self.__line_scan(x, tmp_char_loc)
                    if re.match('trailer', tmp_perm_str[0]): # xref table is complete
                        x_data = {}
                        if not body.has_key('XRef Tables'):
                            body['XRef Tables'] = []
                        body['XRef Tables'].append(xrf_tbl)
                        break
            if re.match('trailer', x[char_loc:char_loc + 7]):
                trailer_offset = char_loc
                if not body.has_key('Trailers'):
                    body['Trailers'] = []
                c += 7
                char_loc = self.__eol_scan(x, c)
                # A trailer keyword is follwed by a dictionary. Process the dict just like an indirect object dict.
                ret = self.__i_object_def_parse(x, c, 'trailer', 'trailer')
                c = ret[1]
                current_position = c
                # Check for obfuscation in named objects!
                try:
                    deob_ret = self.__named_object_deobfuscate(ret[0])
                except Exception as e:
                    self.__error_control(e.__repr__(), e.message, 'trailer: offset: ' + str(current_position))
                deob_ret['Offset'] = trailer_offset
                if deob_ret['Value'].has_key('XRefStm'):
                    if not body.has_key('Start XRef Entries'):
                        body['Start XRef Entries'] = []
                    body['Start XRef Entries'].append(deob_ret['Value']['XRefStm']['Value'])
                if deob_ret['Value'].has_key('Prev'):
                    if not body.has_key('Start XRef Entries'):
                        body['Start XRef Entries'] = []
                    body['Start XRef Entries'].append(deob_ret['Value']['Prev']['Value'])
                body['Trailers'].append(deob_ret)
            if re.match('startxref', x[char_loc:char_loc + 9]):
                if not body.has_key('Start XRef Entries'):
                    body['Start XRef Entries'] = []
                c += 9
                char_loc = self.__eol_scan(x, c)
                xref_end = re.search('%%EOF', x[c:]).start() + c
                xref_offset = x[c:xref_end]
                c = xref_end
                current_position = c
                while True:
                    if re.match('\s', xref_offset):
                        xref_offset = xref_offset[1:]
                    else:
                        if re.search('\s$', xref_offset):
                            xref_offset = xref_offset[:-1]
                        else:
                            break
                body['Start XRef Entries'].append(xref_offset)
            if re.match('%%EOF', x[char_loc:char_loc + 5]):
                c += 5
                current_position = c
                if c >= l:
                    break
                continue
            current_position = c
        return body


    def __get_stream_dimensions(self, x_str, s_point):
        c = s_point
        while True:
            if re.match('\x0D\x0A', x_str[c:]):
                c += 2
                continue
            if re.match('\x0A', x_str[c:]):
                c += 1
                continue
            if re.match('\x0D', x_str[c:]):
                # This "if" block should NEVER execute. If it does, someone is not following the rules.
                # I should increase the malware index for these shenanigans.
                c += 1
                continue
            break
        stream_start = c
        if re.search('endstream', x_str[c:]):
            end_stream = re.search('endstream', x_str[c:]).start()
            end_stream_pos = c + end_stream
            c += re.search('endstream', x_str[c:]).end()
            '''
            if re.match('\x0D\x0Aendstream', x_str[end_stream_pos - 2:c]):
                end_stream -= 2
            else:
                if re.match('\x0Aendstream', x_str[end_stream_pos - 1:c]):
                    end_stream -= 1
            length_stream = end_stream
            '''
        else:
            return 'exception(Missing \'endstream\')', c, '', ''

        return c, stream_start


    def __i_object_parse(self, x_str):
        def compress_spaces(y_str):
            # Compress multple spaces. We don't need them.
            c = y_str[0]
            temp_str = y_str
            remove_count = 0
            while True:
                if re.search('  ', temp_str):
                    temp_str = temp_str.replace('  ', ' ', 1)
                    remove_count += 1
                else:
                    break
            return temp_str, remove_count


        def strip_everything_else(y_str):
            c = y_str[0]
            temp_str = y_str
            remove_count = len(re.findall('(\x00|\x09|\x0A|\x0D)', temp_str))
            while True: # Why did I even make this a loop? No matter what happens it only executes once....
                if remove_count > 0:
                    temp_str = temp_str.replace('\x00', '')
                    temp_str = temp_str.replace('\x09', '')
                    temp_str = temp_str.replace('\x0A', '')
                    temp_str = temp_str.replace('\x0D', '')
                    return temp_str, remove_count
                else:
                    break
            return temp_str, remove_count

        new_str = []
        new_str.append(x_str)
        new_str.append(0)
        new_str = strip_everything_else(new_str[0])
        new_str2 = compress_spaces(new_str[0])
        # Check if this is an object definition:
        if re.search('obj$', new_str[0]):
            if re.match('[\d]+\s[\d]+\sobj', new_str2[0]):
                return 'obj', new_str2, (new_str[1] + new_str2[1])
            else:
                raise Exception('__i_object_parse(): This is not an indirect object')
        else:
            raise Exception('__i_object_parse(): This is not an indirect object')


    def __update_mal_index(self, num, index):
        self.__overall_mal_index[index] += num
        if self.__overall_mal_index[index] > 255:
            self.__overall_mal_index[index] = 255
        return


    def __i_object_def_parse(self, x_str, s_point, o_type, cur_obj):
        def __point_check(arr, point):
            for i in arr:
                if point < i['Offset']:
                    continue
                else:
                    if point >= i['Offset'] and point < (i['Offset'] + i['Length']):
                        return 'Invalid', (i['Offset'] + i['Length'] - point)
            return 'Valid', point


        def __string_search(datas, position = 0):
            strings = []
            t_pos = position  # Keeping track of position within dict here
            b_pos = t_pos
            temp_str = datas[t_pos:]
            top_str = datas
            last_offset = 0
            last_length = 0

            c = 0  # Counter to keep track of nesting. When this reaches zero, we're done

            while True:
                if re.search('\(', top_str):
                    s_start = re.search('\(', top_str).start()
                    # Make sure it's not escaped.
                    es_start = re.search('\\\\\(', top_str[s_start - 1:s_start + 1])
                    if es_start == None: # We have an open parentheses thats not escaped. Begin literal string!
                        strings.append({'Offset': s_start + last_offset + last_length, 'Length': ''})
                        last_offset = last_offset + s_start
                        l_strings = len(strings)
                        temp_str = temp_str[s_start + 1:]
                        b_pos += s_start + 1
                        c += 1
                        while True:
                            try:
                                boundary = re.search('\(|\)', top_str[b_pos:]).start()
                            except:
                                return 'Error: (Fatal: Malformed literal string.)'
                            b_pos += boundary
                            seq = top_str[b_pos:b_pos + 1]
                            if seq == ')' and re.search('\\\\\)', top_str[b_pos - 1:b_pos + 1]) == None:
                                b_pos += 1
                                c -= 1
                            if seq == ')' and not re.search('\\\\\)', top_str[b_pos - 1:b_pos + 1]) == None:
                                if not re.search('\\\\\\\\\)', top_str[b_pos - 2:b_pos + 1]) == None:
                                    b_pos += 1
                                    c -= 1
                                else:
                                    b_pos += 1
                            if seq == '(' and re.search('\\\\\(', top_str[b_pos - 1:b_pos + 1]) == None:
                                b_pos += 1
                                c += 1
                            if seq == '(' and not re.search('\\\\\(', top_str[b_pos - 1:b_pos + 1]) == None:
                                b_pos += 1
                            new_str = (top_str[s_start:b_pos])
                            temp_str = temp_str[boundary + 1:]
                            if c == 0:
                                length = len(new_str)
                                end = strings[l_strings - 1]['Offset'] + (length - 1)
                                strings[l_strings - 1]['Length'] = length
                                strings[l_strings - 1]['End'] = end
                                last_length = last_length + len(new_str)
                                top_str = temp_str
                                b_pos = 0
                                break
                else:
                    break
            return strings


        def __comment_search(datas, str_array, position = 0):
            initial_comment = []
            comment_points = []
            pos = position

            while True:
                if re.search('%', datas[pos:]):
                    s_start = re.search('%', datas[pos:]).start()
                    pos += s_start
                    p_check = __point_check(str_array, pos)
                    if p_check[0] == 'Valid':
                        comment_points.append(p_check[1])
                        comment_length = re.search('\x0D|\x0A', datas[pos:]).start()
                        if len(comment_points) > 0:
                            l_comment_point = len(comment_points)
                            offset = comment_points[l_comment_point - 1]
                            end = offset + (comment_length - 1)
                            initial_comment.append({'Offset': offset, 'Length': comment_length, 'End': end})
                            comment_points.pop()
                        pos += 1
                    else:
                        pos += p_check[1]
                else:
                    break
            if len(initial_comment) > 0:
                new_array = sorted(initial_comment, key=lambda k: k['Offset'])
                return new_array
            else:
                return initial_comment


        def __hexstring_search(datas, str_array, position = 0):
            initial_hexstr = []
            hexstr_points = []
            pos = position

            while True:
                if re.search('<|>', datas[pos:]):
                    s_start = re.search('<|>', datas[pos:]).start()
                    pos += s_start
                    p_check = __point_check(str_array, pos)
                    if p_check[0] == 'Valid':
                        char = datas[p_check[1]]
                        if char == '<' and re.search('\\\\<', datas[p_check[1] - 1:p_check[1] + 1]) == None:
                            if re.search('<<', datas[p_check[1]:p_check[1] + 2]):
                                pos += 2
                            else:
                                hexstr_points.append(p_check[1])
                                pos += 1
                        if char == '>' and re.search('\\\\>', datas[p_check[1] - 1:p_check[1] + 1]) == None:
                            if len(hexstr_points) > 0:
                                l_hexstr_point = len(hexstr_points)
                                offset = hexstr_points[l_hexstr_point - 1]
                                length = (p_check[1] + 1) - offset
                                end = offset + (length - 1)
                                initial_hexstr.append({'Offset': offset, 'Length': length, 'End': end})
                                hexstr_points.pop()
                                pos += 1
                            else:
                                pos += 1
                    else:
                        pos += p_check[1]
                else:
                    break
            if len(initial_hexstr) > 0:
                new_array = sorted(initial_hexstr, key=lambda k: k['Offset'])
                return new_array
            else:
                return initial_hexstr


        def __array_search(datas, str_array, position = 0):
            initial_array = []
            array_points = []
            pos = position
            s_length = len(str_array)
            if s_length == 0:
                strings = __string_search(datas)
            else:
                strings = str_array

            while True:
                if re.search('\[|\]', datas[pos:]):
                    s_start = re.search('\[|\]', datas[pos:]).start()
                    pos += s_start
                    p_check = __point_check(strings, pos)
                    if p_check[0] == 'Valid':
                        char = datas[p_check[1]]
                        if char == '[' and re.search('\\\\\[', datas[p_check[1] - 1:p_check[1] + 1]) == None:
                            array_points.append(p_check[1])
                        if char == ']' and re.search('\\\\\]', datas[p_check[1] - 1:p_check[1] + 1]) == None:
                            l_array_point = len(array_points)
                            offset = array_points[l_array_point - 1]
                            length = (p_check[1] + 1) - offset
                            end = offset + (length - 1)
                            initial_array.append({'Offset': offset, 'Length': length, 'End': end})
                            array_points.pop()
                        pos += 1
                    else:
                        pos += p_check[1]
                else:
                    break
            if len(initial_array) > 0:
                new_array = sorted(initial_array, key=lambda k: k['Offset'])
                return new_array
            else:
                return initial_array


        def __dictionary_search(datas, str_array, hex_array, position = 0):
            initial_dicts = []
            dict_points = []
            pos = position

            sh_array = [] # Combining the str and hex arrays
            for i in str_array:
                sh_array.append(i)
            for i in hex_array:
                sh_array.append(i)

            str_hex_array = sorted(sh_array, key=lambda k: k['Offset']) # Sorted str/hex array

            while True:
                if re.search('<<|>>', datas[pos:]):
                    s_start = re.search('<<|>>', datas[pos:]).start()
                    pos += s_start
                    p_check = __point_check(str_hex_array, pos)
                    if p_check[0] == 'Valid':
                        char = datas[p_check[1]:p_check[1] + 2]
                        if char == '<<' and re.search('\\\\<', datas[p_check[1] - 1:p_check[1] + 3]) == None:
                            dict_points.append(p_check[1])
                        if char == '>>' and re.search('\\\\<', datas[p_check[1] - 1:p_check[1] + 3]) == None:
                            l_array_point = len(dict_points)
                            offset = dict_points[l_array_point - 1]
                            length = (p_check[1] + 2) - offset
                            end = offset + (length - 1)
                            initial_dicts.append({'Offset': offset, 'Length': length, 'End': end})
                            dict_points.pop()
                        pos += 2
                    else:
                        pos += p_check[1]
                else:
                    break
            if len(initial_dicts) > 0:
                new_dict = sorted(initial_dicts, key=lambda k: k['Offset'])
                return new_dict
            else:
                return initial_dicts


        def __name_search(datas, str_array, position = 0):
            names_array = []
            pos = position

            while True:
                if re.search('/', datas[pos:]):
                    s_start = re.search('/', datas[pos:]).start()
                    pos += s_start
                    p_check = __point_check(str_array, pos)
                    if p_check[0] == 'Valid':
                        char = datas[p_check[1]]
                        if char == '/' and re.search('\\\\/', datas[p_check[1] - 1:p_check[1] + 1]) == None:
                            names_array.append({'Offset': pos, 'Length': '', 'End': ''})
                            l_names_array = len(names_array)
                            pos += 1
                            char = datas[pos]
                            length = 1
                            while True:
                                if not re.match('[\/\(\)\[\]\<\>\s]', char):
                                    pos += 1
                                    char = datas[pos]
                                    length += 1
                                else:
                                    break
                            names_array[l_names_array - 1]['Length'] = length
                            end = pos - 1
                            names_array[l_names_array - 1]['End'] = end
                    else:
                        pos += p_check[1]
                else:
                    break
            return names_array


        def __indirect_ref_search(datas, str_array, position = 0):
            ref_array = []
            pos = position

            while True:
                if re.search('(\s|\[|\))[0-9]{1,6}\s[0-9]{1,6}\sR(\s|<|>|\/|\[|\]|\(|\x09|\x0D|\x0A)', datas[pos:]):
                    s_start = re.search('(\s|\[|\))[0-9]{1,6}\s[0-9]{1,6}\sR(\s|<|>|\/|\[|\]|\(|\x09|\x0D|\x0A)', datas[pos:]).start()
                    s_start += 1
                    s_end = re.search('(\s|\[|\))[0-9]{1,6}\s[0-9]{1,6}\sR(\s|<|>|\/|\[|\]|\(|\x09|\x0D|\x0A)', datas[pos:]).end()
                    s_end -= 2
                    pos += s_start
                    p_check = __point_check(str_array, pos)
                    if p_check[0] == 'Valid':
                        length = (s_end - s_start) + 1
                        end = pos + length - 1
                        ref_array.append({'Offset': pos, 'Length': length, 'End': end})
                        pos += length
                    else:
                        pos += p_check[1]
                else:
                    break
            return ref_array


        def __unknown_search(datas, str_array, comment_array, hex_array, array_array, names_array,
                             indirect_ref_array, dict_array, position):
            unks_array = []
            pos = position
            all_array = [] # Combining all the arrays

            for i in str_array:
                all_array.append(i)
            for i in comment_array:
                all_array.append(i)
            for i in hex_array:
                all_array.append(i)
            for i in names_array:
                all_array.append(i)
            for i in indirect_ref_array:
                all_array.append(i)

            all_array = sorted(all_array, key=lambda k: k['Offset'])

            while True:
                if re.search('[^\x00\x09\x0A\x0D\x0C\x20<>\[\]\/\%]', datas[pos:]):
                    s_start = re.search('[^\x00\x09\x0A\x0D\x0C\x20<>\[\]\/\%]', datas[pos:]).start()
                    pos += s_start
                    p_check = __point_check(all_array, pos)
                    if p_check[0] == 'Invalid':
                        pos += p_check[1]
                        continue
                    else:
                        offset = p_check[1]
                        length = re.search('[\x00\x09\x0A\x0D\x0C\x20<>\[\]\/\%]', datas[offset:]).start()
                        end = offset + (length - 1)
                        unks_array.append({'Offset': offset, 'Length': length, 'End': end})
                        pos += length
                else:
                    break
            return unks_array


        def __object_search(datas, position = 0):
            pos = position
            object_list = {}
            str_list = __string_search(datas, pos)
            object_list['String'] = str_list
            comment_list = __comment_search(datas, str_list, pos)
            object_list['Comment'] = comment_list
            hex_list = __hexstring_search(datas, str_list, pos)
            object_list['Hex'] = hex_list
            array_list = __array_search(datas, str_list, pos)
            object_list['Array'] = array_list
            names_list = __name_search(datas, str_list)
            object_list['Name'] = names_list
            indirect_ref_list = __indirect_ref_search(datas, str_list, pos)
            object_list['Indirect Reference'] = indirect_ref_list
            dict_list = __dictionary_search(datas, str_list, hex_list, pos)
            object_list['Dict'] = dict_list
            unk_list = __unknown_search(datas, str_list, comment_list,
                                        hex_list, array_list, names_list,
                                        indirect_ref_list, dict_list, pos)
            object_list['Unknown'] = unk_list
            list_points = []
            for i in object_list:
                for j in object_list[i]:
                    list_points.append({'Type': i, 'Offset': j['Offset'], 'Length': j['Length'], 'End': j['End']})
            list_points = sorted(list_points, key=lambda k: k['Offset'])
            return list_points


        def __assemble_object_structure(datas, object_points, cur_obj, data_type = 'Value', eod = '', position = 0):
            def point_type(object_points, point):
                for i in object_points:
                    if i['Offset'] == point:
                        return i['Type'], i['End'], i['Length']
                return None, ''

            def eval_none(char, k_val, pos):
                k_type = 'Unknown'
                curr_val = k_val
                curr_pos = pos
                if re.search('[^\s\<\>\[\]\(\)\/]', char):
                    curr_val += char
                curr_pos += 1
                return k_type, curr_val, curr_pos
                #return curr_val, curr_pos

            def eval_name(k_val, pos):
                k_type = 'Named Object'
                curr_val = k_val
                curr_pos = pos + 1
                return k_type, curr_val, curr_pos


            if data_type == 'Value' or data_type == 'Name' or data_type == 'String':
                x = ''
            if data_type == 'Dict':
                x = {}
            if data_type == 'Array':
                x = []

            length = len(datas)
            if eod == '':
                end = length
            else:
                end = eod

            pos = re.search('[^\s]', datas).start()
            pos += position
            key = True
            temp_dict = {}

            while pos < length and pos < end:
                k_val = ''
                k_type = ''
                v_val = ''
                v_type = ''

                while key:
                    if data_type == 'Array':
                        if len(k_val) > 0:
                            x.append({'Value Type': k_type, 'Value': k_val})
                            k_type = ''
                            k_val = ''
                    p_type = point_type(object_points, pos)
                    if p_type[0] == None:
                        pos += 1

                    if p_type[0] == 'Comment':
                        pos = p_type[1] + 1

                    if p_type[0] == 'Hex':
                        k_type = 'Hexidecimal String'
                        k_val = datas[pos + 1:p_type[1]]
                        pos = p_type[1] + 1

                    if p_type[0] == 'String':
                        k_type = 'Literal String'
                        k_val = datas[pos + 1:p_type[1]]
                        pos = p_type[1] + 1
                        if self.__is_crypted:
                            if not cur_obj in self.__crypt_handler_info['o_ignore']:
                                k_val = self.crypto.decrypt(self.__crypt_handler_info, k_val.encode('hex'), k_type, cur_obj)

                    if p_type[0] == 'Dict':
                        k_type = 'Dictionary'
                        pos += 2
                        ret = __assemble_object_structure(datas, object_points, cur_obj, 'Dict', p_type[1] + 1, pos)
                        k_val = ret
                        pos = p_type[1] + 1

                    if p_type[0] == 'Array':
                        k_type = 'Array'
                        pos += 1
                        ret = __assemble_object_structure(datas, object_points, cur_obj, 'Array', p_type[1] + 1, pos)
                        pos = p_type[1] + 1
                        k_val = ret

                    if p_type[0] == 'Unknown':
                        k_type = 'Unknown'
                        k_val = datas[pos:p_type[1] + 1]
                        pos = p_type[1] + 1

                    if p_type[0] == 'Indirect Reference':
                        k_type = 'Indirect Reference'
                        k_val = datas[pos:p_type[1] + 1]
                        pos = p_type[1] + 1

                    if p_type[0] == 'Name':
                        k_type, k_val, pos = eval_name(datas[pos + 1:p_type[1] + 1], p_type[1])
                        key = False

                    if pos >= end:
                        break

                while not key:
                    if data_type == 'Array':
                        if len(k_val) > 0:
                            x.append(k_val)
                            k_val = ''
                            key = True
                            break
                    p_type = point_type(object_points, pos)
                    if p_type[0] == None:
                        pos += 1

                    if p_type[0] == 'Comment':
                        pos = p_type[1] + 1

                    if p_type[0] == 'String':
                        v_type = 'Literal String'
                        v_val = datas[pos + 1:p_type[1]]
                        pos = p_type[1] + 1
                        key = True
                        if self.__is_crypted:
                            if not cur_obj in self.__crypt_handler_info['o_ignore']:
                                v_val = self.crypto.decrypt(self.__crypt_handler_info, v_val.encode('hex'), v_type, cur_obj)

                    if p_type[0] == 'Dict':
                        v_type = 'Dictionary'
                        pos += 2
                        ret = __assemble_object_structure(datas, object_points, cur_obj, 'Dict', p_type[1] + 1, pos)
                        v_val = ret
                        pos = p_type[1] + 1
                        key = True

                    if p_type[0] == 'Unknown':
                        v_type = 'Unknown'
                        v_val = datas[pos:p_type[1] + 1]
                        pos = p_type[1] + 1
                        key = True

                    if p_type[0] == 'Indirect Reference':
                        v_type = 'Indirect Reference'
                        v_val = datas[pos:p_type[1] + 1]
                        pos = p_type[1] + 1
                        key = True

                    if p_type[0] == 'Hex':
                        v_type = 'Hexidecimal String'
                        v_val = datas[pos + 1:p_type[1]]
                        pos = p_type[1] + 1
                        key = True

                    if p_type[0] == 'Name':
                        v_type, v_val, pos = eval_name(datas[pos + 1:p_type[1] + 1], p_type[1])
                        key = True

                    if p_type[0] == 'Array':
                        v_type = 'Array'
                        pos += 1
                        ret = __assemble_object_structure(datas, object_points, cur_obj, 'Array', p_type[1] + 1, pos)
                        pos = p_type[1] + 1
                        v_val = ret
                        key = True

                    if pos >= end:
                        break

                if len(k_val) > 0 and len(v_val) > 0 or type(v_val) == list:
                    temp_dict[k_val] = {'Value Type': v_type, 'Value': v_val}

            if data_type == 'Dict':
                return temp_dict

            if data_type == 'Array':
                if len(temp_dict) > 0 and len(x) == 0:
                    x.append(temp_dict)
                return x

            if data_type == 'Value': # We might be in root call of this function
                if type(k_val) == dict:
                    temp_dict = {'Value Type': 'Dictionary', 'Value': k_val}
                    return temp_dict
                if type(k_val) == str:
                    temp_dict = {'Value Type': k_type, 'Value': k_val}
                    return temp_dict
                if type(k_val) == list:
                    temp_dict = {'Value Type': k_type, 'Value': k_val}
                    return temp_dict


        def __find_xs_whitespace(x, obj, def_obj_data):
            def __compute_depth(x, depth, end):
                i = 0
                while i < len(x):
                    if x[i]['Offset'] > end:
                        break
                    if x[i]['Type'] == 'Dict' or x[i]['Type'] == 'Array':
                        if not x[i].has_key('Depth'):
                            x[i]['Depth'] = depth
                            last_i = __compute_depth(x[i + 1:], (depth + 1), x[i]['End'])
                            i += (last_i + 1)
                    else:
                        if not x[i].has_key('Depth'):
                            x[i]['Depth'] = depth
                            i += 1
                return i


            def __check_it(data):
                if re.search('\x20\x0D', data) or re.search('\x20\x0A', data) or re.search('\x0D\x20', data) or \
                        re.search('\x0A\x20', data) or len(re.findall('\x20', data)) > 1 or \
                        len(re.findall('\x0D', data)) > 1 or len(re.findall('\x0A', data)) > 1:
                    self.__update_mal_index(1, 7)
                return


            __compute_depth(x, 0, x[0]['End'])
            depth_tracker = {}
            depth_tracker[0] = [0, 0]
            depth_roots = {}
            depth_roots[0] = {'Depth Dimensions': x[0]}
            prev_depth = 0
            threshold = 3 # Whitespace threshold. Too small and it triggers F+.
                          # Setting to 3 to provide leeway for misc PDF creation applications

            for i in range(1, len(x)):
                diff = 0
                if x[i].has_key('Depth'):
                    cur_depth = x[i]['Depth']
                else:
                    cur_depth = prev_depth
                if cur_depth < prev_depth:
                    for j in range((len(depth_roots) - 1), (cur_depth - 1), -1):
                        diff = depth_roots[j]['Depth Dimensions']['End'] - (x[depth_tracker[prev_depth][1]]['End'] + 1)
                        data = def_obj_data[(x[depth_tracker[prev_depth][1]]['End'] + 1):depth_roots[j]['Depth Dimensions']['End']]
                        depth_tracker.pop(prev_depth)
                        depth_roots.pop(prev_depth - 1)
                        prev_depth -= 1
                        if diff > threshold:
                            __check_it(data)
                prev_depth = cur_depth
                if not depth_tracker.has_key(cur_depth):
                    depth_tracker[cur_depth] = []
                    depth_tracker[cur_depth].append(i)
                else:
                    depth_tracker[cur_depth][0] = depth_tracker[cur_depth][1]
                    depth_tracker[cur_depth].pop(1)

                depth_tracker[cur_depth].append(i)
                if depth_tracker[cur_depth][1] == depth_tracker[cur_depth][0]:
                    first_seen = True # First time depth has been encountered.
                    depth_roots[cur_depth - 1] = {'Depth Dimensions': x[i - 1]}
                else:
                    first_seen = False
                if first_seen:
                    if x[depth_tracker[cur_depth - 1][1]]['Type'] == 'Dict':
                        diff = x[depth_tracker[cur_depth][1]]['Offset'] - (x[depth_tracker[cur_depth -1][1]]['Offset'] + 2)
                    if x[depth_tracker[cur_depth - 1][1]]['Type'] == 'Array':
                        diff = x[depth_tracker[cur_depth][1]]['Offset'] - (x[depth_tracker[cur_depth -1][1]]['Offset'] + 1)
                    data = def_obj_data[x[depth_tracker[cur_depth - 1][1]]['Offset']:x[depth_tracker[cur_depth][1]]['Offset']]
                else:
                    diff = x[depth_tracker[cur_depth][1]]['Offset'] - (x[depth_tracker[cur_depth][0]]['Length'] + (x[depth_tracker[cur_depth][0]]['Offset'])+ 1)
                    data = def_obj_data[(x[depth_tracker[cur_depth][0]]['Offset']+x[depth_tracker[cur_depth][0]]['Length']):x[depth_tracker[cur_depth][1]]['Offset']]
                if diff > threshold:
                    __check_it(data)
            end = x[-1]['End'] +1
            for i in range(len(depth_roots), 0, -1):
                diff = (depth_roots[i - 1]['Depth Dimensions']['End'] + 1) - end
                data = def_obj_data[end:(depth_roots[i - 1]['Depth Dimensions']['End'] + 1)]
                if diff > threshold:
                    __check_it(data)
                end += diff
            return


        c = s_point
        l = len(x_str)
        def_end = 0
        while True:
            char_loc = self.__eol_scan(x_str, c)
            if char_loc == l:
                break # We reached the end of the file. Peace out!
            if re.match('\s', x_str[char_loc]):
                # Got spaces in between objects. Proceed to next position.
                c += 1
                continue
            if re.match('%', x_str[char_loc]):
                # Got comment before object definition
                c = self.__line_scan(x_str, char_loc)[1]
                continue
            c = char_loc
            break
        # We're at the start of an indirect object definition
        if o_type == 'obj' or o_type == 'objstm':
            def_end = re.search('(endobj|stream\x0D|stream\x0A)', x_str[c:]).start()
        if o_type == 'trailer':
            if re.search('startxref', x_str[c:]):
                def_end = re.search('startxref', x_str[c:]).start()
            else:
                self.__error_control('SpecViolation', 'startxref entry is missing')
        def_obj_data = x_str[c:c + def_end]
        x = __object_search(def_obj_data)
        if not o_type == 'objstm': # Exclude compressed object streams from the whitespace check.
            __find_xs_whitespace(x, cur_obj, def_obj_data) # Disable the whitespace checker here if gens false positives.
        if o_type == 'trailer':
            def_obj_data = def_obj_data[0:x[0]['Length']]
        y = __assemble_object_structure(def_obj_data, x, cur_obj)
        return y, (def_end + c)


    def __eol_scan(self, x_str, s_point):
        #print 'eol_scan(x_str = %s)' % x_str
        # This function scans through 1 or more EOL characters and returns
        # the offset of the first non-EOL character encountered.
        c = s_point
        l = len(x_str)
        while True:
            if x_str[c] == '\x0D' or x_str[c] == '\x0A':
                c += 1
                if c == l:
                    break
            else:
                break
        return c


    def __named_object_deobfuscate(self, data):
        def deobfuscate(x):
            temp_x = ''
            lx = len(x)
            c = 0  # c = index of the value stored in x
            # There should be no need to obfuscate the below chars.
            # If that's being done, it's probably malware.
            normal_chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
            mal_index = 0
            # Now check what's stored in x and make sure it isn't obfuscated...
            while True:
                if x[c] == '#': # <--- Hex encoding detected!
                    chars = x[c + 1: c + 3]
                    if len(chars) == 2 and re.match('[a-fA-F0-9]{2}', chars):
                        hex_char = chr(int(x[c + 1: c + 3], 16))
                    else:
                        raise SpecViolation('Invalid chars after \'#\'')
                    if hex_char in normal_chars: # Shouldn't have needed to encode a normal char.
                        mal_index += 1
                    temp_x += hex_char
                    c += 3
                else:
                    temp_x += x[c]
                    c += 1
                if c >= lx:
                    break
            self.__update_mal_index(mal_index, 6)
            return temp_x

        temp_x = ''  # storing new value of x here
        while True:
            if not type(data) == dict:
                return data
            if data.has_key('Value Type'): # Check array of Differences!
                if data['Value Type'] == 'Named Object':
                    ret = deobfuscate(data['Value'])
                    data['Value'] = ret
                    return data
                if data['Value Type'] == 'Dictionary':
                    # Check if keys are obfuscated...
                    new_old_map = {} # Renaming keys while iterating through them causes unpredictable results. Store changes here.
                    for i in data['Value']:
                        try:
                            ret = deobfuscate(i)
                        except Exception as e:
                            raise e
                        new_old_map[i] = ret
                    for i in new_old_map: # Now implememnt those changes...
                        if not i == new_old_map[i]:
                            data['Value'][new_old_map[i]] = data['Value'].pop(i) # Interesting method of renaming keys....
                    # Keys should be deobfuscated. Send the value of each key back into this root function
                    for i in data['Value']:
                        temp_x = self.__named_object_deobfuscate(data['Value'][i])
                if data['Value Type'] == 'Array':
                    for i in range(0, len(data['Value'])):
                        if type(data['Value'][i]) == str:
                            data['Value'][i] = deobfuscate(data['Value'][i])
                        else:
                            temp_x = self.__named_object_deobfuscate(data['Value'][i])
                if not data['Value Type'] == 'Named Object' or data['Value Type'] == 'Dictionary':
                    return data
            else:
                break
        return temp_x


    def __header_scan(self, x):
        headers = {}

        # Checking for version header. Should be at offset 0x00
        h_loc = x.find('%', 0)
        if h_loc > 0:
            self.__error_control('SpecViolation', 'Arbitrary data before header')

        pdf_version = self.__line_scan(x ,h_loc + 1)
        headers['Version'] = {}
        headers['Version']['Value'] = pdf_version[0]
        headers['Version']['Length'] = len(pdf_version[0])
        headers['Version']['Offset'] = h_loc

        # Checking for comment header.
        #s_offset = len(pdf_version) + 1
        s_offset = pdf_version[1]
        ch_loc = self.__eol_scan(x, s_offset)
        if x[ch_loc] == '%':
            # We have a header comment.
            pdf_comment = self.__line_scan(x ,ch_loc + 1)
            headers['Comment'] = {}
            headers['Comment']['Value'] = pdf_comment[0]
            headers['Comment']['Length'] = len(pdf_comment[0])
            headers['Comment']['Offset'] = ch_loc
        return headers


    def __line_scan(self, x_str, s_point):
        # Scans a comment looking for the first EOL character it finds, signifying the end of the comment.
        # Function then returns only the comment with no trailing EOL character.
        c = s_point
        temp_str = ''
        x = True
        while x:
            if not x_str[c] == '\x0D' and not x_str[c] == '\x0A':
                temp_str += x_str[c]
                c += 1
            else:
                x = False
        return temp_str, c


    def __xref_parse(self, x_str, xrf_args, s_point):
        x_table = []
        s = s_point
        for i in range(0, int(xrf_args[1])):
            char_loc = self.__eol_scan(x_str, s)
            data = self.__line_scan(x_str, char_loc)
            if re.match('\d{10}\s\d{5}\s(n|f)', data[0]):
                x_table.append(data[0])
                s = data[1]
            else:
                raise SpecViolation('Invalid XRef table')
        return x_table, s


    def __gen_random_file(self):
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        file_name = "".join(random.sample(chars, 16))
        return file_name


    def get_encryption_handler(self, x, summary, password):
        xref_offsets = []
        xref_tables = []
        trailers = {}
        enc_dict = []
        trailers['Indirect Objects'] = []
        trailers['Trailers'] = []
        sxref_count = len(re.findall('startxref', x))
        if sxref_count == 0:
            self.__error_control('SpecViolation', 'startxref entry is missing')
        pos = 0
        for i in range(0, sxref_count):
            x_start = re.search('startxref', x[pos:]).start() + pos
            pos = (x_start + 9)
            char_loc = self.__eol_scan(x, pos)
            xref_end = re.search('%%EOF', x[pos:]).start() + pos
            xref_offset = x[char_loc:xref_end]
            pos = xref_end
            while True:
                if re.match('\s', xref_offset):
                    xref_offset = xref_offset[1:]
                else:
                    if re.search('\s$', xref_offset):
                        xref_offset = xref_offset[:-1]
                    else:
                        break
            xref_offsets.append(int(xref_offset))
        for i in xref_offsets:
            if not i == 0: # Skip dummy offset for linearized PDFs
                o_type = None
                if re.match('\d{1,8}\s\d{1,5}\sobj', x[i:i + 18]):
                    o_type = 'obj'
                if re.match('xref', x[i:i + 4]):
                    o_type = 'xref'
                if o_type == None:
                    self.__error_control('SpecViolation', 'startxref offset is misaligned.')
                if o_type == 'xref':
                    pos = i + 4
                    while True:
                        char_loc = self.__eol_scan(x, pos)
                        xref_entries = self.__line_scan(x, char_loc)
                        c = xref_entries[1]
                        xref_entries = xref_entries[0].split(' ')

                        try:
                            tmp_xrf_tbl = self.__xref_parse(x, xref_entries, c)
                        except SpecViolation as e:
                            self.__error_control(e.__repr__(), e.message, 'xref: offset: ' + str(c))
                        except Exception as e:
                            self.__error_control(e.__repr__(), e.message,  'xref: offset: ' + str(c))

                        c = tmp_xrf_tbl[1]
                        xref_tables.append({'Offset': i})
                        xref_tables.append(tmp_xrf_tbl[0])

                        tmp_char_loc = self.__eol_scan(x, c)
                        pos = tmp_char_loc
                        tmp_perm_str = self.__line_scan(x, tmp_char_loc)
                        if re.match('trailer', tmp_perm_str[0]): # xref table is complete
                            trailer_offset = tmp_char_loc
                            c = tmp_char_loc + 7
                            char_loc = self.__eol_scan(x, c)

                            ret = self.__i_object_def_parse(x, c, 'trailer', 'trailer')
                            c = ret[1]
                            current_position = c

                            try:
                                deob_ret = self.__named_object_deobfuscate(ret[0])
                            except Exception as e:
                                self.__error_control(e.__repr__(), e.message, 'trailer: offset: ' + str(current_position))
                            if not deob_ret['Value'].has_key('Encrypt'):
                                break
                            if not trailers.has_key('XRef Tables'):
                                trailers['XRef Tables'] = []
                            deob_ret['Offset'] = trailer_offset
                            trailers['Trailers'].append(deob_ret)
                            self.__crypt_handler_info['doc_id'] = trailers['Trailers'][0]['Value']['ID']['Value'][0]['Value'].decode('hex')
                            trailers['XRef Tables'].append(xref_tables)
                            break
                if o_type == 'obj':
                    index = len(trailers['Indirect Objects'])
                    # Trailer is in an indirect object which means the xref table is compressed.
                    # We're gonna have to parse this XRef stream to find the offset of the Encrypt dictionary :/
                    trailer = re.match('\d{1,8}\s\d{1,5}\sobj', x[i:i + 18]).group()
                    pos = (i + len(trailer))
                    s_object = self.__i_object_parse(trailer)
                    trailer = s_object[1][0].replace(' obj', '')
                    self.__crypt_handler_info['o_ignore'].append(trailer)
                    ret_dict = self.__i_object_def_parse(x, pos, 'obj', trailer)
                    if not ret_dict[0]['Value'].has_key('Encrypt'):
                        continue # This is not the droid we are looking for
                    char_loc = self.__eol_scan(x, ret_dict[1])
                    if re.match('stream', x[char_loc:char_loc + 6]):
                        char_loc += 6
                    else:
                        self.__error_control('Exception', 'Missing \'stream\' entry', trailer)
                    ret_stream = self.__get_stream_dimensions(x, char_loc)
                    trailers['Indirect Objects'].append({trailer: ret_dict[0]})
                    # There should be a /Root entry here btw, just in case we decide to care about that right now. :)
                    stream_dimensions = {}
                    if trailers['Indirect Objects'][index][trailer]['Value'].has_key('Length'):
                        stream_dimensions['Length'] = trailers['Indirect Objects'][index][trailer]['Value']['Length']
                    else:
                        self.__error_control('SpecViolation', 'trailer XRef stream is missing \'Length\' value', trailer)
                    stream_dimensions['Start'] = ret_stream[1]
                    trailers['Indirect Objects'][index][trailer]['Stream Dimensions'] = stream_dimensions
                    self.__crypt_handler_info['doc_id'] = trailers['Indirect Objects'][index][trailer]['Value']['ID']['Value'][0]['Value'].decode('hex')
                    self.__process_streams(x, trailers, summary)


        if len(trailers['Indirect Objects']) == 0 and len(trailers['Trailers']) == 0: # We have no Encrypt entries
            return
        else:
            self.__is_crypted = True

        for i in trailers:
            if i == 'Trailers':
                for j in range(0, len(trailers[i])):
                    enc_tmp = trailers[i][j]['Value']['Encrypt']['Value'].replace(' R', '')
                    enc_dict.append({enc_tmp: 'XRef Tables'})
                    self.__crypt_handler_info['o_ignore'].append(enc_tmp)
            if i == 'Indirect Objects':
                for j in range(0, len(trailers[i])):
                    for k in trailers[i][j]:
                        enc_tmp = trailers[i][j][k]['Value']['Encrypt']['Value'].replace(' R', '')
                        enc_dict.append({enc_tmp: 'XRef Streams'})
                        self.__crypt_handler_info['o_ignore'].append(enc_tmp)

        # k... we have the object number that contains the encryption dictionary stored in enc_dict now

        for i in enc_dict:
            offset = [] # Making a list just incase the indirect object we're looking for has been defined more than once
            i_key = i.keys()[0]
            i_val = i.values()[0]
            if i_val == 'XRef Tables':
                for j in trailers[i_val]:
                    for k in j:
                    #for k in j[1]:
                        if type(k) == dict:
                            if k.has_key('Offset'):
                                continue
                        for l in k:
                            tmp_offset = int(re.match('\d{10}', l).group())
                            if re.match(i_key, x[tmp_offset:tmp_offset + 10]): # We have found the offset of our indirect object :)
                                if not tmp_offset in offset:
                                    offset.append(tmp_offset)
            if i_val == 'XRef Streams':
                for j in trailers[i_val]:
                    for k in j:
                        if k.has_key('Type'):
                            if k['Type'] == 'Compressed Object':
                                continue
                            tmp_offset = int(re.match('\d{10}', k['Value']).group())
                            if re.match(i_key, x[tmp_offset:tmp_offset + 10]): # We have found the offset of our indirect object :)
                                if not tmp_offset in offset:
                                    offset.append(tmp_offset)

        # The offsets in the offset variable should be where we will find encryption dictionaries
        for i in offset:
            pos = i
            obj = re.match('\d{1,8}\s\d{1,5}\sobj', x[pos:pos + 18]).group()
            s_object = self.__i_object_parse(obj)
            pos += len(obj)
            obj = s_object[1][0].replace(' obj', '')
            ret_dict = self.__i_object_def_parse(x, pos, 'obj', obj)
            # ret_dict should be our encryption dictionary :)
            if not ret_dict[0]['Value'].has_key('Filter'):
                self.__error_control('SpecViolation', 'Encryption dictionary missing \'Filter\'', obj)
            if not ret_dict[0]['Value']['Filter']['Value'] == 'Standard':
                self.__error_control('Exception', 'Unable to decrypt this document with the provided filter', obj)
            # At this point we have established the filter is standard. Check for existence of other required values now.
            # I am going to require that V be present even though it is only "strongly" recommended that it be there.
            # Without it, V defaults to 0 and per the PDF spec: "An algorithm that is undocumented and no longer supported,"
            # So, in it's absence, I will throw an exception and exit but it is NOT a spec violation.
            if not ret_dict[0]['Value'].has_key('V'):
                self.__error_control('Exception', 'V defaults to 0 which is an unsupported algorithm', obj)
            if not ret_dict[0]['Value'].has_key('R') or \
                not ret_dict[0]['Value'].has_key('O') or \
                not ret_dict[0]['Value'].has_key('U') or \
                not ret_dict[0]['Value'].has_key('P'):
                self.__error_control('SpecViolation', 'Encryption dictionary missing one or more POUR values', obj)
            if not ret_dict[0]['Value'].has_key('Length'):
                self.__crypt_handler_info['key_length'] = 40
            else:
                self.__crypt_handler_info['key_length'] = int(ret_dict[0]['Value']['Length']['Value'])
            # Start setting things...
            if ret_dict[0]['Value']['V']['Value'] == '0' or \
                            ret_dict[0]['Value']['V']['Value'] == '3':
                self.__error_control('Exception', 'Document encrypted with an unsupported version number. Aborting analysis.', obj)
            else:
                V = int(ret_dict[0]['Value']['V']['Value'])

            if ret_dict[0]['Value'].has_key('R'):
                self.__crypt_handler_info['revision'] = int(ret_dict[0]['Value']['R']['Value'])
            else:
                self.__error_control('SpecViolation', 'Encryption dictionary missing revision number.', obj)

            self.__crypt_handler_info['version'] = V

            P = ret_dict[0]['Value']['P']['Value']
            O = None
            U = None
            OE = None
            UE = None
            Perms = None
            if ret_dict[0]['Value']['O']['Value Type'] == 'Hexidecimal String':
                O = ret_dict[0]['Value']['O']['Value']
            if ret_dict[0]['Value']['O']['Value Type'] == 'Literal String':
                O = ret_dict[0]['Value']['O']['Value'].encode('hex')
                O = self.crypto.escaped_string_replacement(O)
            if ret_dict[0]['Value']['U']['Value Type'] == 'Hexidecimal String':
                U = ret_dict[0]['Value']['U']['Value']
            if ret_dict[0]['Value']['U']['Value Type'] == 'Literal String':
                U = ret_dict[0]['Value']['U']['Value'].encode('hex')
                U = self.crypto.escaped_string_replacement(U)
            if O == None or U == None:
                raise Exception('Decryption error: O or U is invalid. Aborting analysis.')

            if V >= 4:
                if not ret_dict[0]['Value'].has_key('CF'):
                    self.__error_control('SpecViolation', 'Encryption dictionary missing V4 CF value', obj)
                if not ret_dict[0]['Value'].has_key('StmF'):
                    self.__crypt_handler_info['StmF'] = 'Identity'
                else:
                    self.__crypt_handler_info['StmF'] = ret_dict[0]['Value']['StmF']['Value']
                    if not ret_dict[0]['Value']['CF']['Value'].has_key(self.__crypt_handler_info['StmF']) and \
                            not self.__crypt_handler_info['StmF'] == 'Identity':
                        self.__error_control('SpecViolation', 'Crypt filter doesn\'t exist', obj)
                if not ret_dict[0]['Value'].has_key('StrF'):
                    self.__crypt_handler_info['StrF'] = 'Identity'
                else:
                    self.__crypt_handler_info['StrF'] = ret_dict[0]['Value']['StrF']['Value']
                    if not ret_dict[0]['Value']['CF']['Value'].has_key(self.__crypt_handler_info['StrF']) and \
                            not self.__crypt_handler_info['StrF'] == 'Identity':
                        self.__error_control('SpecViolation', 'Crypt filter doesn\'t exist', obj)
                self.__crypt_handler_info['method'] = ret_dict[0]['Value']['CF']['Value']['StdCF']['Value']['CFM']['Value']
                if re.match('AES', self.__crypt_handler_info['method']):
                    self.__crypt_handler_info['salted'] = True
                else:
                    self.__crypt_handler_info['salted'] = False
                if ret_dict[0]['Value'].has_key('EncryptMetadata'):
                    if ret_dict[0]['Value']['EncryptMetadata']['Value'] == 'false':
                        self.__crypt_handler_info['encrypt_metadata'] = False
                    else:
                        self.__crypt_handler_info['encrypt_metadata'] = True
                else:
                    self.__crypt_handler_info['encrypt_metadata'] = True

            if not self.__crypt_handler_info.has_key('method'):
                self.__crypt_handler_info['method'] = 'RC4'

            if V == 5:
                if ret_dict[0]['Value']['OE']['Value Type'] == 'Hexidecimal String':
                    OE = ret_dict[0]['Value']['OE']['Value']
                if ret_dict[0]['Value']['OE']['Value Type'] == 'Literal String':
                    OE = ret_dict[0]['Value']['OE']['Value'].encode('hex')
                    OE = self.crypto.escaped_string_replacement(OE)
                if ret_dict[0]['Value']['UE']['Value Type'] == 'Hexidecimal String':
                    UE = ret_dict[0]['Value']['UE']['Value']
                if ret_dict[0]['Value']['UE']['Value Type'] == 'Literal String':
                    UE = ret_dict[0]['Value']['UE']['Value'].encode('hex')
                    UE = self.crypto.escaped_string_replacement(UE)
                if ret_dict[0]['Value']['Perms']['Value Type'] == 'Hexidecimal String':
                    Perms = ret_dict[0]['Value']['Perms']['Value']
                if ret_dict[0]['Value']['Perms']['Value Type'] == 'Literal String':
                    Perms = ret_dict[0]['Value']['Perms']['Value'].encode('hex')
                    Perms = self.crypto.escaped_string_replacement(Perms)
                if OE == None or UE == None or Perms == None:
                    raise Exception('Decryption error: OE or UE is invalid. Aborting analysis.')

            if V >= 6:
                self.__error_control('Exception', 'Document encrypted with an unsupported version number. Aborting analysis.', obj)

            self.__crypt_handler_info['O'] = O.decode('hex')
            self.__crypt_handler_info['P'] = P
            self.__crypt_handler_info['U'] = U.decode('hex')
            if OE:
                self.__crypt_handler_info['OE'] = OE.decode('hex')
            if UE:
                self.__crypt_handler_info['UE'] = UE.decode('hex')
            if Perms:
                self.__crypt_handler_info['Perms'] = Perms.decode('hex')
