import re
import zlib
import hashlib
import random
import os
from tempfile import gettempdir
from platform import system as platform_sys


__VERSION__ = ('v1.0')
__AUTHOR__ = ('Shane King <kingaling_at_meatchicken_dot_net>')

class PyDF2JSON(object):

    # Thing you might wanna change. The default for the below items is 'False' because they are very verbose.
    # Example: Adding a decompressed 50K jpeg to the json output is probably not necessary unless you have need.
    # But, the below items will be hashed and the hash will placed into the json structure

    # show_ttf: Place true type fonts streams in json output. Default is False.
    show_ttf = False

    # show_bitmaps: Place bitmap streams in json output. Default is False.
    show_bitmaps = False

    # show_pics: Place picture streams in json output. Default is False.
    show_pics = False

    # show_embedded_files: Pretty much all other types of files. Default is False.
    show_embedded_files = False

    # dump_streams: Dump streams to a temp location. Using this for LaikaBOSS objects.
    dump_streams = False

    # No touchie...
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

    # Malware Index:
    # Each index has a max value of 0xFF (255)

    # 00 00 00 00 00 00 00 00
    # |  |  |  |  |  |  |  |____ Unnecessary whitespace.
    # |  |  |  |  |  |  |_______ Named object obfuscation.
    # |  |  |  |  |  |__________ Not used yet (Misaligned object locations) *
    # |  |  |  |  |_____________ Not used yet (Javascript) *
    # |  |  |  |________________ Not used yet
    # |  |  |___________________ Not used yet
    # |  |______________________ Not used yet
    # |_________________________ Not used yet (Only 1 page and it contains Javascript) *

    # Starred items (*) will be calculated during PDF summary


    def GetPDF(self, x):
        PDF = {}
        PDF['Size'] = len(x)

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
            PDF['Temp File Location'] = self.dump_loc

        # Verify we have PDF here.
        PDF['Header'] = self.__header_scan(x)

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

        # Proceed with PDF body processing
        PDF['Body'] = self.__body_scan(x, s_offset)

        # Assemble a summary of things.
        PDF['Summary'] = {}
        # Find Object Streams...
        PDF['Summary']['Object Streams'] = self.__pdf_summary(PDF['Body'], 'objstm')
        # Find URIs...
        PDF['Summary']['URI List'] = self.__pdf_summary(PDF['Body'], 'uri')
        # Get a count of pages
        catalogstuff = self.__pdf_summary(PDF['Body'], 'catalog')
        PDF['Summary']['Catalogs'] = catalogstuff[0]
        PDF['Summary']['Pages'] = catalogstuff[1]
        PDF['Summary']['Names'] = catalogstuff[2]
        PDF['Summary']['Outlines'] = catalogstuff[3]
        PDF['Summary']['OpenAction'] = catalogstuff[4]
        PDF['Summary']['AcroForm'] = catalogstuff[5]
        PDF['Summary']['AA'] = catalogstuff[6]
        PDF['Summary']['JavaScript'] = catalogstuff[7]
        PDF['Summary']['EmbeddedFiles'] = catalogstuff[8]
        PDF['Summary']['Page Count'] = self.__pdf_summary(PDF['Body'], 'pagecount', PDF['Summary']['Pages'])
        ## Now that I have the page count, I don't care about the Pages entry...
        #PDF['Summary'].pop('Pages') # Bye, pages
        # Get Javascript
        PDF['Summary']['JS'] = self.__pdf_summary(PDF['Body'], 'js')
        # Find Launch actions
        PDF['Summary']['Launch'] = self.__pdf_summary(PDF['Body'], 'launch')
        # Get embedded files count
        PDF['Summary']['Embedded Files'] = self.__pdf_summary(PDF['Body'], 'embedded', PDF['Summary']['EmbeddedFiles'])

        # Calc overall malware index
        om_index = ''
        for i in self.__overall_mal_index:
            om_index += format(i, 'x').zfill(2)

        # Do this to convert from decimal to hex string with no leading '0x' : format(decimal, 'x').zfill(16)

        PDF['Malware Index'] = int(om_index, 16)
        return PDF


    def __pdf_summary(self, pdfjson, sum_type, optional_data = None):
        def __list_uri(data, uri, obj, objstm = None):
            if type(data) == dict:
                if data.has_key('Value Type'):
                    if data['Value Type'] == 'Dictionary' or data['Value Type'] == 'Array':
                        __list_uri(data['Value'], uri, obj, objstm)
                else:
                    for i in data:
                        if i == 'URI':
                            if objstm == None:
                                uri.append({obj: data[i]['Value']})
                            else:
                                if len(uri) > 0:
                                    for j in range(0, len(uri)):
                                        if type(uri[j]) == dict:
                                            if uri[j].has_key(objstm):
                                                uri[j][objstm][obj] = data[i]['Value']
                                            else:
                                                uri.append({objstm: {obj: data[i]['Value']}})
                                else:
                                    uri.append({objstm: {obj: data[i]['Value']}})
                        else:
                            __list_uri(data[i], uri, obj, objstm)

            if type(data) == list:
                for i in range(0, len(data)):
                    __list_uri(data[i], uri, obj, objstm)

            return uri


        def __find_javascript(data, javascript, obj, objstm = None):
            if type(data) == dict:
                if data.has_key('Value Type'):
                    if data['Value Type'] == 'Dictionary' or data['Value Type'] == 'Array':
                        __find_javascript(data['Value'], javascript, obj, objstm)
                else:
                    for i in data:
                        if i == 'S':
                            if data[i]['Value'] == 'JavaScript':
                                if objstm == None:
                                    javascript.append({obj: data[i]['Value']})
                                else:
                                    if len(javascript) > 0:
                                        for j in range(0, len(javascript)):
                                            if type(javascript[j]) == dict:
                                                if javascript[j].has_key(objstm):
                                                    javascript[j][objstm][obj] = data[i]['Value']
                                                else:
                                                    javascript.append({objstm: {obj: data[i]['Value']}})
                                    else:
                                        javascript.append({objstm: {obj: data[i]['Value']}})
                        else:
                            __find_javascript(data[i], javascript, obj, objstm)

            if type(data) == list:
                for i in range(0, len(data)):
                    __find_javascript(data[i], javascript, obj, objstm)

            return javascript


        def __find_launch(data, launch, obj, objstm = None):
            if type(data) == dict:
                if data.has_key('Value Type'):
                    if data['Value Type'] == 'Dictionary' or data['Value Type'] == 'Array':
                        __find_launch(data['Value'], launch, obj, objstm)
                else:
                    for i in data:
                        if i == 'S':
                            if data[i]['Value'] == 'Launch':
                                if objstm == None:
                                    launch.append({obj: data[i]['Value']})
                                else:
                                    if len(launch) > 0:
                                        for j in range(0, len(launch)):
                                            if type(launch[j]) == dict:
                                                if launch[j].has_key(objstm):
                                                    launch[j][objstm][obj] = data[i]['Value']
                                                else:
                                                    launch.append({objstm: {obj: data[i]['Value']}})
                                    else:
                                        launch.append({objstm: {obj: data[i]['Value']}})
                        else:
                            __find_launch(data[i], launch, obj, objstm)

            if type(data) == list:
                for i in range(0, len(data)):
                    __find_launch(data[i], launch, obj, objstm)

            return launch


        def __find_catalog(data):
            if type(data) == dict:
                if data.has_key('Value') and data['Value Type'] == 'Dictionary':
                    if data['Value'].has_key('Type'):
                        if data['Value']['Type'].has_key('Value'):
                            if data['Value']['Type']['Value'] == 'Catalog':
                                return j
            return

        if sum_type == 'uri':
            uri = []
            for i in range(0,len(pdfjson['Indirect Objects'])):
                for j in pdfjson['Indirect Objects'][i]:
                    __list_uri(pdfjson['Indirect Objects'][i][j], uri, j)
                for j in pdfjson['Indirect Objects'][i]:
                    if pdfjson['Indirect Objects'][i][j].has_key('Decoded Object Stream'):
                        for k in pdfjson['Indirect Objects'][i][j]['Decoded Object Stream']:
                            __list_uri(pdfjson['Indirect Objects'][i][j]['Decoded Object Stream'][k], uri, k, j)
            return uri

        if sum_type == 'objstm':
            objstm = []
            for i in range(0,len(pdfjson['Indirect Objects'])):
                for j in pdfjson['Indirect Objects'][i]:
                    if pdfjson['Indirect Objects'][i][j].has_key('Value') and \
                                    pdfjson['Indirect Objects'][i][j]['Value Type'] == 'Dictionary':
                        if pdfjson['Indirect Objects'][i][j]['Value'].has_key('Type'):
                            if pdfjson['Indirect Objects'][i][j]['Value']['Type'].has_key('Value'):
                                if pdfjson['Indirect Objects'][i][j]['Value']['Type']['Value'] == 'ObjStm':
                                    objstm.append(j)
            return objstm

        if sum_type == 'embedded':
            embedded = []
            if len(optional_data) > 0: # We got an EmbeddedFiles entry in our summary. Woot!
                for i in range(0, len(optional_data)):
                    for j in range(0, len(pdfjson['Indirect Objects'])):
                        if pdfjson['Indirect Objects'][j].has_key(optional_data[i]): # We found matching indirect object
                            tmp = pdfjson['Indirect Objects'][j][optional_data[i]]['Value']['EmbeddedFiles']['Value']
                            tmp = tmp.replace(' R', '')
                            # Now process the object noted in tmp...
                            for k in range(0, len(pdfjson['Indirect Objects'])):
                                if pdfjson['Indirect Objects'][k].has_key(tmp):
                                    if pdfjson['Indirect Objects'][k][tmp].has_key('Value Type'):
                                        if pdfjson['Indirect Objects'][k][tmp]['Value Type'] == 'Dictionary':
                                            if pdfjson['Indirect Objects'][k][tmp]['Value'].has_key("Names"):
                                                if pdfjson['Indirect Objects'][k][tmp]['Value']['Names'].has_key('Value Type'):
                                                    if pdfjson['Indirect Objects'][k][tmp]['Value']['Names']['Value Type'] == 'Array':
                                                        for l in range(0, len(pdfjson['Indirect Objects'][k][tmp]['Value']['Names']['Value']), 2):
                                                            embedded.append({pdfjson['Indirect Objects'][k][tmp]['Value']['Names']['Value'][l]['Value']:
                                                                                 pdfjson['Indirect Objects'][k][tmp]['Value']['Names']['Value'][l + 1]['Value']})
            return embedded

        if sum_type == 'js':
            js = []
            for i in range(0,len(pdfjson['Indirect Objects'])):
                for j in pdfjson['Indirect Objects'][i]:
                    __find_javascript(pdfjson['Indirect Objects'][i][j], js, j)
                for j in pdfjson['Indirect Objects'][i]:
                    if pdfjson['Indirect Objects'][i][j].has_key('Decoded Object Stream'):
                        for k in pdfjson['Indirect Objects'][i][j]['Decoded Object Stream']:
                            __find_javascript(pdfjson['Indirect Objects'][i][j]['Decoded Object Stream'][k], js, k, j)
            return js

        if sum_type == 'launch':
            launch = []
            for i in range(0,len(pdfjson['Indirect Objects'])):
                for j in pdfjson['Indirect Objects'][i]:
                    __find_launch(pdfjson['Indirect Objects'][i][j], launch, j)
                for j in pdfjson['Indirect Objects'][i]:
                    if pdfjson['Indirect Objects'][i][j].has_key('Decoded Object Stream'):
                        for k in pdfjson['Indirect Objects'][i][j]['Decoded Object Stream']:
                            __find_launch(pdfjson['Indirect Objects'][i][j]['Decoded Object Stream'][k], launch, k, j)
            return launch

        if sum_type == 'catalog':
            catalogs = []
            pages = []
            openactions = []
            acroforms = []
            aa = []
            outlines = []
            names = []
            javascript = []
            embeddedfiles = []
            for i in range(0,len(pdfjson['Indirect Objects'])):
                for j in pdfjson['Indirect Objects'][i]:
                    catalog = __find_catalog(pdfjson['Indirect Objects'][i][j])
                    if not catalog == None:
                        catalogs.append(catalog)
            for i in catalogs:
                # Get /Pages named object. It's required to be there.
                for j in range(0,len(pdfjson['Indirect Objects'])):
                    if pdfjson['Indirect Objects'][j].has_key(i):
                        if pdfjson['Indirect Objects'][j][i]['Value'].has_key('Pages'):
                            if len(pages) > 0:
                                pages_exists = False
                                for k in pages:
                                    if pdfjson['Indirect Objects'][j][i]['Value']['Pages']['Value'] in k.values():
                                        pages_exists = True
                                if not pages_exists:
                                    # Because there is no need to add an object that points to same indirect object as another
                                    pages.append({i: pdfjson['Indirect Objects'][j][i]['Value']['Pages']['Value']})
                            else:
                                pages.append({i: pdfjson['Indirect Objects'][j][i]['Value']['Pages']['Value']})
                        else:
                            print 'Invalid PDF. Catalog is missing the named object \'/Pages\''
                            print 'Alert the media (AKA: @kingaling)'
                            exit()
                        if pdfjson['Indirect Objects'][j][i]['Value'].has_key('Names'):
                            if len(names) > 0:
                                names_exist = False
                                for k in names:
                                    if pdfjson['Indirect Objects'][j][i]['Value']['Names']['Value'] in k.values():
                                        names_exists = True
                                if not names_exist:
                                    names.append({i: pdfjson['Indirect Objects'][j][i]['Value']['Names']['Value']})
                            else:
                                names.append({i: pdfjson['Indirect Objects'][j][i]['Value']['Names']['Value']})
                        if pdfjson['Indirect Objects'][j][i]['Value'].has_key('Outlines'):
                            if len(outlines) > 0:
                                outlines_exist = False
                                for k in outlines:
                                    if pdfjson['Indirect Objects'][j][i]['Value']['Outlines']['Value'] in k.values():
                                        outlines_exists = True
                                if not outlines_exist:
                                    outlines.append({i: pdfjson['Indirect Objects'][j][i]['Value']['Outlines']['Value']})
                            else:
                                outlines.append({i: pdfjson['Indirect Objects'][j][i]['Value']['Outlines']['Value']})
                        if pdfjson['Indirect Objects'][j][i]['Value'].has_key('OpenAction'):
                            if len(openactions) > 0:
                                openactions_exist = False
                                for k in openactions:
                                    if pdfjson['Indirect Objects'][j][i]['Value']['OpenAction']['Value'] in k.values():
                                        openactions_exists = True
                                if not openactions_exist:
                                    openactions.append({i: pdfjson['Indirect Objects'][j][i]['Value']['OpenAction']['Value']})
                            else:
                                openactions.append({i: pdfjson['Indirect Objects'][j][i]['Value']['OpenAction']['Value']})
                        if pdfjson['Indirect Objects'][j][i]['Value'].has_key('AcroForm'):
                            if len(acroforms) > 0:
                                acroforms_exist = False
                                for k in acroforms:
                                    if pdfjson['Indirect Objects'][j][i]['Value']['AcroForm']['Value'] in k.values():
                                        acroforms_exist = True
                                if not acroforms_exist:
                                    acroforms.append(
                                        {i: pdfjson['Indirect Objects'][j][i]['Value']['AcroForm']['Value']})
                            else:
                                acroforms.append(
                                    {i: pdfjson['Indirect Objects'][j][i]['Value']['AcroForm']['Value']})
                        if pdfjson['Indirect Objects'][j][i]['Value'].has_key('AA'):
                            if len(aa) > 0:
                                aa_exist = False
                                for k in aa:
                                    if pdfjson['Indirect Objects'][j][i]['Value']['AA']['Value'] in k.values():
                                        aa_exists = True
                                if not aa_exist:
                                    aa.append(
                                        {i: pdfjson['Indirect Objects'][j][i]['Value']['AA']['Value']})
                            else:
                                aa.append(
                                    {i: pdfjson['Indirect Objects'][j][i]['Value']['AA']['Value']})
            # Populate javascript and ambeddefiles lists by using our assembled names list:
            if len(names) > 0:
                for i in range(0, len(names)):
                    if type(names[i]) == dict:
                        for j in names[i]:
                            name_tree = names[i][j]
                            name_tree = name_tree.replace(' R', '')
                            # Access the name tree and check for /JavaScript and /EmbeddedFiles entries
                            for k in range(0, len(pdfjson['Indirect Objects'])):
                                if pdfjson['Indirect Objects'][k].has_key(name_tree):
                                    if pdfjson['Indirect Objects'][k][name_tree].has_key('Value'):
                                        if pdfjson['Indirect Objects'][k][name_tree]['Value'].has_key('JavaScript'):
                                            javascript.append(name_tree)
                                        if pdfjson['Indirect Objects'][k][name_tree]['Value'].has_key('EmbeddedFiles'):
                                            embeddedfiles.append(name_tree)
                                for l in pdfjson['Indirect Objects'][k]:
                                    if pdfjson['Indirect Objects'][k][l].has_key('Decoded Object Stream'):
                                        if pdfjson['Indirect Objects'][k][l]['Decoded Object Stream'].has_key(name_tree):
                                            if pdfjson['Indirect Objects'][k][l]['Decoded Object Stream'][name_tree].has_key('Value'):
                                                if pdfjson['Indirect Objects'][k][l]['Decoded Object Stream'][name_tree]['Value'].has_key('JavaScript'):
                                                    javascript.append(name_tree)
                                                if pdfjson['Indirect Objects'][k][l]['Decoded Object Stream'][name_tree]['Value'].has_key('EmbeddedFiles'):
                                                    embeddedfiles.append(name_tree)

            return catalogs, pages, names, outlines, openactions, acroforms, aa, javascript, embeddedfiles

        if sum_type == 'pagecount':
            pagecount = 0
            if len(optional_data) > 1:
                i_ref = optional_data[-1:][0].values()[0]
            else:
                i_ref = optional_data[0].values()[0]
            i_ref = i_ref.replace(' R', '')
            for i in range(0,len(pdfjson['Indirect Objects'])):
                if pdfjson['Indirect Objects'][i].has_key(i_ref):
                    if type(pdfjson['Indirect Objects'][i][i_ref]) == dict:
                        if pdfjson['Indirect Objects'][i][i_ref].has_key('Value'):
                            if pdfjson['Indirect Objects'][i][i_ref]['Value'].has_key('Count'):
                                if pdfjson['Indirect Objects'][i][i_ref]['Value']['Count']['Value Type'] == 'Indirect Object':
                                    print 'The page count is stored in some other object'
                                    continue
                                if pdfjson['Indirect Objects'][i][i_ref]['Value']['Count']['Value Type'] == 'Unknown':
                                    pagecount = int(pdfjson['Indirect Objects'][i][i_ref]['Value']['Count']['Value'])

                else:
                    # Check for decoded object streams...
                    for j in pdfjson['Indirect Objects'][i]:
                        if pdfjson['Indirect Objects'][i][j].has_key('Decoded Object Stream'):
                            for k in pdfjson['Indirect Objects'][i][j]['Decoded Object Stream']:
                                if k == i_ref:
                                    if pdfjson['Indirect Objects'][i][j]['Decoded Object Stream'][i_ref]['Value'].has_key('Count'):
                                        if pdfjson['Indirect Objects'][i][j]['Decoded Object Stream'][i_ref]['Value']['Count']['Value Type'] == 'Indirect Object':
                                            print 'The page count is stored in some other object'
                                            continue
                                        if pdfjson['Indirect Objects'][i][j]['Decoded Object Stream'][i_ref]['Value']['Count']['Value Type'] == 'Unknown':
                                            pagecount = int(pdfjson['Indirect Objects'][i][j]['Decoded Object Stream'][i_ref]['Value']['Count']['Value'])

            return pagecount



    def __header_scan(self, x):
        headers = {}

        # Checking for version header. Should be at offset 0x00
        h_loc = x.find('%', 0)
        if h_loc > 0:
            print 'Extra bytes before header. Exiting...'
            exit()
        if h_loc < 0:
            print 'Not a PDF. Exiting...'
            exit()
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


    def __body_scan(self, x, s_point):
        c = s_point
        l = len(x)
        mal_index = 0
        body = {}

        stream_displays = {
            'ttf': self.show_ttf,
            'bitmap': self.show_bitmaps,
            'graphic': self.show_pics,
            'olecf': self.show_embedded_files,
            'docx': self.show_embedded_files,
            'xlsx': self.show_embedded_files,
            'zip': self.show_embedded_files,
            'Unknown': True
        }
        known_stream_types = [
            'XRef',
            'ObjStm'
        ]

        current_position = -1
        last_position = c
        while True:
            if last_position == current_position:
                # We have an infinite loop in progress if we don't increment by at least 1 here.
                # Probably caused by arbitrary data in the PDF. Might wanna increase the malware index.
                c += 1
            if c >= l:
                break
            last_position = c
            current_position = last_position
            char_loc = self.__eol_scan(x, c)
            if char_loc == l:
                break # We reached the end of the file. Peace out!
            if re.match('\s', x[char_loc]):
                # Got spaces in between objects. Proceede to next position.
                c += 1
                current_position = c
                continue
            c = char_loc
            current_position = c
            if re.match('\d{1,10}\s\d{1,10}\sobj', x[char_loc:char_loc + 26]):
                # See if we've encountered an indirect object. We probably have.
                if re.search('obj', x[char_loc:]):
                    search_end = re.search('obj', x[char_loc:]).end()
                    temp_indirect_obj = x[char_loc:char_loc + search_end]
                    s_object = self.__i_object_parse(temp_indirect_obj)
                    cur_obj = s_object[1][0].replace(' obj', '')
                    cur_val = {}
                    cur_val['Offset'] = char_loc
                    mal_index += s_object[2]
                    self.__update_mal_index(mal_index, 7)
                    if s_object[0] == 'obj': # We have a valid indirect object
                        c += search_end
                        if not body.has_key('Indirect Objects'):
                            body['Indirect Objects'] = []
                        index = len(body['Indirect Objects'])
                        # Since we have a valid indirect object identifier, parse the indirect object definition.
                        ret = self.__i_object_def_parse(x, c, 'obj')
                        c = ret[1]
                        # Check for obfuscation in named objects!
                        if len(ret[0]) > 0:
                            deob_ret = self.__named_object_deobfuscate(ret[0])
                            cur_val['Value Type'] = deob_ret['Value Type']
                            cur_val['Value'] = deob_ret['Value']
                        else:
                            cur_val['Value Type'] = None
                            cur_val['Value'] = ''
                        body['Indirect Objects'].append({cur_obj: cur_val})
                        del cur_val
                        if re.match('endobj', x[c:]):
                            c += 6
                            current_position = c
                            continue
                        if re.match('stream', x[c:]):
                            c += 6
                            ret = self.__process_stream(x, body['Indirect Objects'][index][cur_obj]['Value'], c)
                            c = ret[1]
                            if ret[2] == '':
                                stream_type = 'Unknown'
                            else:
                                stream_type = ret[2] # This is returned from __process_stream() function
                            if not stream_type == None:
                                if stream_displays[stream_type]:
                                    body['Indirect Objects'][index][cur_obj]['Stream Data'] = ret[0]
                            else:
                                body['Indirect Objects'][index][cur_obj]['Stream Data'] = ''

                            if self.dump_streams:
                                dump_file = self.__gen_random_file()
                                open(self.dump_loc + dump_file, 'wb').write(ret[0])
                                body['Indirect Objects'][index][cur_obj]['Stream Dump Location'] = self.dump_loc + dump_file

                            if body['Indirect Objects'][index][cur_obj]['Value'].has_key('Type'):
                                if body['Indirect Objects'][index][cur_obj]['Value']['Type']['Value'] in known_stream_types:
                                    body['Indirect Objects'][index][cur_obj]['Stream Type'] = \
                                        body['Indirect Objects'][index][cur_obj]['Value']['Type']['Value']
                                else:
                                    body['Indirect Objects'][index][cur_obj]['Stream Type'] = stream_type
                            else:
                                body['Indirect Objects'][index][cur_obj]['Stream Type'] = stream_type
                            body['Indirect Objects'][index][cur_obj]['Stream Hashes'] = ret[3]
                            # Further stream processing goes here. These will depend on stream type.
                            # ....
                            if body['Indirect Objects'][index][cur_obj]['Stream Type'] == 'ObjStm':
                                obj_stream = self.__process_object_stream(body['Indirect Objects'][index][cur_obj]['Stream Data'],
                                                                          body['Indirect Objects'][index][cur_obj]['Value'])
                                body['Indirect Objects'][index][cur_obj]['Decoded Object Stream'] = obj_stream
                                # Since we now have the decoded ObjStm, having the previous "Stream Data" section is
                                # redundant. We have already hashed it so, removing it...
                                if body['Indirect Objects'][index][cur_obj].has_key('Stream Data'):
                                    body['Indirect Objects'][index][cur_obj].pop('Stream Data')

                            if body['Indirect Objects'][index][cur_obj]['Stream Type'] == 'XRef':
                                xref_stream = self.__process_xref_stream(body['Indirect Objects'][index][cur_obj]['Stream Data'],
                                                                         body['Indirect Objects'][index][cur_obj]['Value'])
                                body['Indirect Objects'][index][cur_obj]['Decoded XRef Stream'] = xref_stream
                                # Since we now have the decoded XRef, having the previous "Stream Data" section is
                                # redundant. We have already hashed it so, removing it...
                                if body['Indirect Objects'][index][cur_obj].has_key('Stream Data'):
                                    body['Indirect Objects'][index][cur_obj].pop('Stream Data')

                            if re.search('endobj', x[c:]):
                                c += re.search('endobj', x[c:]).end()
                                current_position = c
                                continue
                    else:
                        print 'We have an invalid object. Exiting...'
                        exit()
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
                    tmp_xrf_tbl = self.__xref_parse(x, xref_entries, c)
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
                if not body.has_key('Trailers'):
                    body['Trailers'] = []
                c += 7
                char_loc = self.__eol_scan(x, c)
                # A trailer keyword is follwed by a dictionary. Process the dict just like an indirect object dict.
                ret = self.__i_object_def_parse(x, c, 'trailer')
                c = ret[1]
                current_position = c
                # Check for obfuscation in named objects!
                deob_ret = self.__named_object_deobfuscate(ret[0])
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
                    hex_char = chr(int(x[c + 1: c + 3], 16))
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
                    for i in data['Value']:
                        ret = deobfuscate(i)
                        data['Value'][ret] = data['Value'].pop(i)
                    # Keys should be deobfuscated. Send the value of each key back into this root function
                    for i in data['Value']:
                        x = self.__named_object_deobfuscate(data['Value'][i])
                if data['Value Type'] == 'Array':
                    for i in data['Value']:
                        x = self.__named_object_deobfuscate(i)
                if not data['Value Type'] == 'Named Object' or data['Value Type'] == 'Dictionary':
                    return data
            else:
                break
        return temp_x


    def __update_mal_index(self, num, index):
        self.__overall_mal_index[index] += num
        if self.__overall_mal_index[index] > 255:
            self.__overall_mal_index[index] = 255
        return


    def __process_xref_stream(self, obj_stream, values):
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

            print 'Error: (__process_xref_stream() -> data_parse()) Fatal: Invalid data type in XRef stream. Exiting.'
            exit()

        len_obj_stream = len(obj_stream)
        field_count = len(values['W']['Value'])
        wfield_1, wfield_2, wfield_3 = '', '', ''
        if not field_count == 3:
            print 'XRef stream doesn\'t specify enough fields!'
            exit()
        loop_count = 0
        while True:
            if loop_count == 0:
                wfield_1 = int(values['W']['Value'][0]['Value'])
                if wfield_1 == 0:
                    print 'Error: (__process_xref_stream) Field 1 = 0. I wanna see this PDF. plz send!'
                    exit()
            if loop_count == 1:
                wfield_2 = int(values['W']['Value'][1]['Value'])
                if wfield_2 == 0:
                    print 'Error: (__process_xref_stream) Field 2 = 0. I wanna see this PDF. plz send!'
                    exit()
            if loop_count == 2:
                wfield_3 = int(values['W']['Value'][2]['Value'])
                if wfield_2 == 0:
                    print 'Error: (__process_xref_stream) Field 3 = 0. I wanna see this PDF. plz send!'
                    exit()
            loop_count += 1
            if loop_count > field_count:
                break
        if wfield_1 == '' or wfield_2 == '' or wfield_3 == '':
            print 'Something happened parsing XRef stream fields!'
            exit()

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
        return xref_tbl


    def __process_object_stream(self, obj_stream, values):
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
        for i in range(0, len(new_obj_stream)):
            curr_i_object = new_obj_stream[i]['Indirect Object']
            if i < (len(new_obj_stream) - 1):
                curr_obj = objects[new_obj_stream[i]['Offset']:new_obj_stream[i + 1]['Offset']]
            else: # Last entry
                curr_obj = objects[new_obj_stream[i]['Offset']:]
            curr_obj += ' endobj'
            i_obj_data = self.__i_object_def_parse(curr_obj, 0, 'obj')
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
                print '__i_object_parse:(Error: This is not an indirect object)'
        else:
            print '__i_object_parse:(Error: This is not an indirect object)'
        exit()


    def __xref_parse(self, x_str, xrf_args, s_point):
        x_table = []
        s = s_point
        for i in range(0, int(xrf_args[1])):
            char_loc = self.__eol_scan(x_str, s)
            data = self.__line_scan(x_str, char_loc)
            x_table.append(data[0])
            s = data[1]
        return x_table, s


    def __i_object_def_parse(self, x_str, s_point, o_type):
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


        def __object_search(datas, position = 0):
            pos = position
            object_list = {}
            str_list = __string_search(datas, pos)
            object_list['String'] = str_list
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
            list_points = []
            for i in object_list:
                for j in object_list[i]:
                    list_points.append({'Type': i, 'Offset': j['Offset'], 'Length': j['Length'], 'End': j['End']})
            list_points = sorted(list_points, key=lambda k: k['Offset'])
            return list_points


        def __assemble_object_structure(datas, object_points, data_type = 'Value', eod = '', position = 0):
            def point_type(object_points, point):
                for i in object_points:
                    if i['Offset'] == point:
                        return i['Type'], i['End'], i['Length']
                return None, ''

            def set_structure(point_type):
                data_structure = ''
                if point_type == 'Dict':
                    data_structure = {}
                if point_type == 'Array':
                    data_structure = []
                if point_type == 'String' or point_type == 'Hex' or point_type == 'Name':
                    data_structure = ''
                return data_structure


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
                while key: # We are assembling a key name
                    p_type = point_type(object_points, pos)
                    if p_type[0] == None:
                        if re.search('[^\s\<\>\[\]\(\)\/]', datas[pos]):
                            k_type = 'Unknown'
                            k_val += datas[pos]
                            pos += 1
                        else:
                            if k_val == '':
                                pos += 1
                            else:
                                key = False
                    if p_type[0] == 'Dict':
                        k_type = 'Dictionary'
                        pos += 2
                        ret = __assemble_object_structure(datas, object_points, 'Dict', p_type[1] + 1, pos)
                        k_val = ret
                        pos = p_type[1] + 1
                    if p_type[0] == 'Indirect Reference':
                        if not k_val == '':
                            break
                        k_type = 'Indirect Reference'
                        k_val = datas[pos:p_type[1] + 1]
                        pos = p_type[1] + 1
                        key = True
                        key = False
                    if p_type[0] == 'Hex':
                        k_type = 'Hex'
                        k_val = datas[pos + 1:p_type[1]]
                        pos = p_type[1] + 1
                        key = False
                    if p_type[0] == 'Name':
                        k_type = 'Named Object'
                        k_val = datas[pos + 1:p_type[1] + 1]
                        pos = p_type[1] + 1
                        ret = __assemble_object_structure(datas, object_points, 'Name', p_type[1] + 1, pos)
                        key = False
                    if p_type[0] == 'String':
                        k_type = 'Literal String'
                        k_val = datas[pos + 1:p_type[1]]
                        pos = p_type[1] + 1
                        key = False
                    if p_type[0] == 'Array':
                        k_type = 'Array'
                        pos += 1
                        ret = __assemble_object_structure(datas, object_points, 'Array', p_type[1] + 1, pos)
                        k_val = ret
                        pos = p_type[1] + 1
                    if pos >= end:
                        break
                while not key:
                    if data_type == 'Array':
                        key = True
                        break
                    p_type = point_type(object_points, pos)
                    if p_type[0] == None:
                        if re.search('[^\s\<\>\[\]\(\)\/]', datas[pos]):
                            v_type = 'Unknown'
                            v_val += datas[pos]
                            pos += 1
                        else:
                            if v_val == '':
                                pos += 1
                            else:
                                key = True
                    if p_type[0] == 'Dict':
                        pos += 2
                        ret = __assemble_object_structure(datas, object_points, 'Dict', p_type[1] + 1, pos)
                        v_val = ret
                        v_type = 'Dictionary'
                        pos = p_type[1] + 1
                        key = True
                    if p_type[0] == 'Indirect Reference':
                        v_type = 'Indirect Reference'
                        v_val = datas[pos:p_type[1] + 1]
                        pos = p_type[1] + 1
                        key = True
                    if p_type[0] == 'String':
                        v_type = 'Literal String'
                        v_val = datas[pos + 1:p_type[1]]
                        pos = p_type[1] + 1
                        key = True
                    if p_type[0] == 'Hex':
                        v_type = 'Hexidecimal String'
                        v_val = datas[pos + 1:p_type[1]]
                        pos = p_type[1] + 1
                        key = True
                    if p_type[0] == 'Name':
                        if len(v_val) > 0: # We already have a value and now we just found a name. Do some shit...
                            key = True
                            break
                        v_type = 'Named Object'
                        v_val = datas[pos + 1:p_type[1] + 1]
                        pos = p_type[1] + 1
                        key = True
                    if p_type[0] == 'Array':
                        if temp_dict.has_key('Type') and \
                            temp_dict['Type']['Value'] == 'Encoding':
                            v_val = []
                            v_val.append(datas[pos + 1:pos + (p_type[2] - 1)])
                            pos += p_type[2]
                            v_type  ='Array'
                            key = True
                        else:
                            pos += 1
                            ret = __assemble_object_structure(datas, object_points, 'Array', p_type[1] + 1, pos)
                            v_val = ret
                            v_type = 'Array'
                            pos = p_type[1] + 1
                            key = True
                    if pos >= end:
                        break
                if len(k_val) > 0 and (len(v_val) > 0 or type(v_val) == list) or type(v_val) == dict: # We have a key value pair. Add them to x.
                    temp_dict[k_val] = {'Value Type': v_type, 'Value': v_val}
                if len(k_val) > 0 and v_val == '':
                    # We have a single value stored in k_val and is now the overall value of this function.
                    # Check if we're in an array
                    if data_type == 'Array':
                        x.append({'Value Type': k_type, 'Value': k_val})
                        #k_val = ''
                    else:
                        x = {'Value Type': k_type, 'Value': k_val}
                if k_type == 'Array' and len(k_val) == 0: # We have an empty array as a key
                    if data_type == 'Value': # We are probably in the root call of this function. x may be wrong data type...
                        if len(x) == 0:
                            x = {'Value Type': k_type, 'Value': k_val}
            if data_type == 'Dict':
                x = temp_dict
            return x

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
            c = char_loc
            break
        # We're at the start of an indirect object definition
        if o_type == 'obj':
            def_end = re.search('(endobj|stream\x0D|stream\x0A)', x_str[c:]).start()
        if o_type == 'trailer':
            def_end = re.search('startxref', x_str[c:]).start()
        def_obj_data = x_str[c:c + def_end]
        x = __object_search(def_obj_data)
        if o_type == 'trailer':
            def_obj_data = def_obj_data[0:x[0]['Length']]
        y = __assemble_object_structure(def_obj_data, x)
        return y, (def_end + c)


    def __process_stream(self, x_str, object_def, s_point):
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
        length_stream = ''
        if object_def.has_key('Length'):
            if not object_def['Length']['Value Type'] == 'Indirect Reference':
                length_stream = int(object_def['Length']['Value'])
                c += length_stream
            else:
                # Manually get the length...
                end_stream = ''
                if re.search('endstream', x_str[c:]):
                    end_stream = re.search('endstream', x_str[c:]).start()
                    end_stream_pos = c + end_stream
                    c += re.search('endstream', x_str[c:]).end()
                    if re.match('\x0D\x0Aendstream', x_str[end_stream_pos - 2:c]):
                        end_stream -= 2
                    else:
                        if re.match('\x0Aendstream', x_str[end_stream_pos - 1:c]):
                            end_stream -= 1
                    length_stream = end_stream
                if length_stream == '':
                    print 'There is a problem with the stream length. Exiting.'
                    exit()
        else:
            length_stream = 'Unknown'
            print 'A length key is required for stream objects. Malformed PDF. Exiting.'
            exit()
        stream_data = x_str[stream_start:stream_start + length_stream]
        # Now get any stream decoding parameters...
        if object_def.has_key('Filter'):
            filters = object_def['Filter']
            if object_def.has_key('DecodeParms'):
                decodeparms = object_def['DecodeParms']
            else:
                if object_def.has_key('DP'):
                    decodeparms = object_def['DP']
                else:
                    decodeparms = []
            # Checking something for later here...
            if len(decodeparms) > 0:
                if decodeparms['Value Type'] == 'Array': # Alert the media
                    print 'We have an array of decode parameters. Exiting. Fix your code!'
                    exit()
            if filters['Value Type'] == 'Array':
                new_filters = []
                for i in filters['Value']:
                    new_filters.append(i['Value'])
                filters = new_filters
            else:
                new_filters = []
                new_filters.append(filters['Value'])
                filters = new_filters
            if len(decodeparms) > 0:
                decodeparms = decodeparms['Value']
            if length_stream == 0:
                return stream_data, c, None, ''
            decoded_stream = self.__filter_parse(stream_data, filters, decodeparms)
            stream_data = decoded_stream

        stream_type = self.__identify_stream(stream_data)
        stream_hash = self.__hash_stream(stream_data)
        if stream_type == '': # Check type entry.
            if object_def.has_key('Type'):
                if object_def['Type']['Value'] == 'XObject':
                    stream_type = 'graphic'
            if not object_def.has_key('Type') and object_def.has_key('Subtype'):
                if object_def['Subtype']['Value'] == 'Image':
                    stream_type = 'graphic'
        return stream_data, c, stream_type, stream_hash


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


    def __filter_parse(self, my_stream, filters, decodeparms):
        ignore_filters = {
            'DCTDecode',
            'CCITTFaxDecode'
        }
        known_encoders = {
            'FlateDecode',
            'ASCIIHexDecode',
            'ASCII85Decode'
        }
        new_stream = my_stream
        num_filters = len(filters)
        num_decodeparms = len(decodeparms)
        if num_decodeparms > 0:
            decoders = True
        else:
            decoders = False
        # num_filters should equal num_decodeparms

        for i in range(0, num_filters):
            if filters[i] in ignore_filters:
                continue
            if filters[i] == 'FlateDecode':
                new_stream = self.__flatedecode(new_stream)
                if decoders:
                    if type(decodeparms) == dict:
                        if decodeparms.has_key('Predictor'):
                            if decodeparms['Predictor'] == 1:
                                continue
                            if decodeparms['Predictor'] == 2:
                                new_stream = self.__decoder_tiff()
                            if decodeparms['Predictor'] > 2:
                                new_stream = self.__decoder_png(new_stream, decodeparms)
                    if type(decodeparms) == list:
                        print 'Error: __filter_parse: Can\'t handle lists of decodeparms yet'
                        exit()
            if filters[i] == 'ASCIIHexDecode':
                new_stream = self.__asciihexdecode(new_stream)
            if filters[i] == 'ASCII85Decode':
                new_stream = self.__ascii85_decode(new_stream)
            if not filters[i] in known_encoders:
                print '__filter_parse(Error: Unknown decoder): %s' % filters[i]
                exit()
        if new_stream == '':
            return my_stream
        else:
            return new_stream


    def __ascii85_decode(self, my_stream):
        base85_charset = '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstu'
        new_encoded = my_stream
        decoded = ''
        remainder = len(my_stream) % 5

        if not remainder == 0:
            padding = (5 - remainder)
        else:
            padding = 0

        if padding > 0:
            for i in range(0, padding):
                new_encoded += 'u'
        else:
            new_encoded = my_stream

        for i in range(0, len(new_encoded), 5):
            x = new_encoded[i: i + 5]
            y = 0
            for j in range(0, len(x)):
                y += base85_charset.index(x[j]) * (85 ** (len(x) - (j + 1)))
            yy = y
            loop = 0
            while True:
                if yy < 256:
                    decoded += chr(yy)
                    break
                z = (yy / 256)
                if z < 256:
                    loop += 1
                    decoded += chr(z)
                    yy = y - (z * (256 ** loop))
                    y = yy
                    loop = 0
                else:
                    loop += 1
                    yy = int(yy / 256)
        if padding > 0 and len(decoded) > 0:
            for i in range(0, padding):
                decoded = decoded[:-1]

        return decoded


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
        rows = len(my_stream) / (num_columns + 1)
        predictor = ord(my_stream[0])
        row_1_data = my_stream[1:num_columns + 1]

        if predictor < 2:
            start_row = 0
            decoded_data = ''
        else:
            start_row = 1
            decoded_data = row_1_data

        for row in range(start_row, rows - 1):
            predictor = ord(my_stream[(row * (num_columns + 1))])

            if predictor == 0:
                decoded_data += algo_0(row_1_data, num_columns)
            if predictor == 1:
                row_1_data = my_stream[(row * (num_columns + 1)) + 1:(row * (num_columns + 1)) + (num_columns + 1)]
                decoded_data += algo_1(row_1_data)
            if predictor == 2:
                row_1_data = decoded_data[-num_columns:]
                row_2_data = my_stream[(row * (num_columns + 1)) + 1:(row * (num_columns + 1)) + (num_columns + 1)]
                decoded_data += algo_2(row_1_data, row_2_data)
            if predictor == 3:
                print 'predictor = 3. Oh noes! Exiting...'
                exit()
                decoded_data += algo_3(my_stream, num_columns)
            if predictor == 4:
                print 'predictor = 4. Oh noes! Exiting...'
                exit()
                decoded_data += algo_4(my_stream, num_columns)
            if predictor == 5:
                print 'predictor = 5. Oh noes! Exiting...'
                exit()
                decoded_data += algo_5(my_stream, num_columns)

        return decoded_data


    def __decoder_tiff(self):
        return


    def __flatedecode(self, i_buffer):
        data = zlib.decompress(i_buffer)

        return data


    def __gen_random_file(self):
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        file_name = "".join(random.sample(chars, 16))
        return file_name