import re
import zlib
import hashlib
import random
import os
from tempfile import gettempdir
from platform import system as platform_sys


__version__ = ('2.0.8')
__author__ = ('Shane King <kingaling_at_meatchicken_dot_net>')


class SpecViolation(Exception):
    pass

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

    # Keeping track of errors
    __error_list = []

    # Malware Index:
    # Each index has a max value of 0xFF (255)

    # 00 00 00 00 00 00 00 00
    # |  |  |  |  |  |  |  |____ Unnecessary whitespace.
    # |  |  |  |  |  |  |_______ Named object obfuscation.
    # |  |  |  |  |  |__________ Not used yet (Misaligned object locations) *
    # |  |  |  |  |_____________ Not used yet (Javascript) *
    # |  |  |  |________________ Not used yet
    # |  |  |___________________ Not used yet
    # |  |______________________ Not used yet (Only 1 page and it contains Javascript) *
    # |_________________________ Not used yet (Malformed PDF / Processing error encountered)

    # Starred items (*) will be calculated during PDF summary


    def __error_control(self, etype, message, misc=''):
        if re.match('SpecViolation', etype):
            raise SpecViolation('SpecViolation' + '(' + message + ' (' + misc + ')' + ')')


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

        # Proceed with PDF body processing
        try:
            PDF['Body'] = self.__body_scan(x, s_offset)
        except Exception as e:
            raise e
        #PDF['Body'] = self.__body_scan(x, s_offset) # Debugging...
        # The above line got all indirect objects, trailers, xref tables etc
        # and preserved the position and length of all streams.
        # Now go get the streams... :)
        try:
            self.__process_streams(x, PDF['Body'])
        except Exception as e:
            raise e

         # Create object map.
        omap = {}
        omap['IO'] = {}
        omap['OS'] = {}
        omap['IO Offsets'] = {}
        omap['XR Offsets'] = []
        self.__assemble_map(PDF['Body'], omap)

        # Assemble a summary of things.
        summary = {}
        try:
            ret = self.__get_summary(PDF, summary, omap)
        except Exception as e:
            raise e

        # Calc overall malware index
        om_index = ''
        for i in self.__overall_mal_index:
            om_index += format(i, 'x').zfill(2)

        # Do this to convert from decimal to hex string with no leading '0x' : format(decimal, 'x').zfill(16)

        PDF['Malware Index'] = int(om_index, 16)
        return PDF, omap, summary


    def __get_summary(self, pdf, summary, omap):
        action_types = {
            'SubmitForm': 'F',
            'Launch': 'F required if no Win, Win Requires a sub F',
            'URI': 'URI',
            'JavaScript': 'JS'
        }
        processed_objects = []

        def __find_root():
            # Find the root objects via trailer entry...
            root_objects = []
            if pdf['Body'].has_key('Trailers'):
                for i in range(0, len(pdf['Body']['Trailers'])):
                    if pdf['Body']['Trailers'][i]['Value'].has_key('Root'):
                        root_entry = pdf['Body']['Trailers'][i]['Value']['Root']['Value'].replace(' R', '')
                        if not root_entry in root_objects:
                            root_objects.append(root_entry)

            if pdf['Body'].has_key('Start XRef Entries'):
                xref_entries = []
            else:
                self.__update_mal_index(255, 0)
                print 'exception(startxref missing)'
                return 'exception(startxref missing)'

            for i in pdf['Body']['Start XRef Entries']:
                if not i == str(0): # Dummy xref table pointer for linear PDF's on page 1 of document.
                    xref_entries.append(int(i))

            if len(xref_entries) < 1:
                self.__update_mal_index(255, 0)
                print 'exception(startxref missing)'
                return 'exception(startxref missing)'

            # Go find more root objects
            for i in xref_entries:
                # Check map for this offset. If' it's not found, xref tables are mis-aligned and this is probably malware.
                if not omap['IO Offsets'].has_key(i) and not i in omap['XR Offsets']:
                    self.__error_list.append('__format-error (Mis-aligned XRef Table)')
                    xref_alignment = False
                    self.__update_mal_index(10, 0)
                else:
                    xref_alignment = True

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
                        if pdf['Body']['Indirect Objects'][io_index][obj]['Value'].has_key('Root'):
                            tmp_root_obj = pdf['Body']['Indirect Objects'][io_index][obj]['Value']['Root']['Value'].replace(' R', '')
                            if not tmp_root_obj in root_objects:
                                root_objects.append(tmp_root_obj)

            if  len(root_objects) == 0:
                self.__error_control('SpecViolation', 'Required \'Root\' entry missing.')

            return root_objects, xref_entries


        def __get_catalog_data():
            # Make sure we're dealing with objects of type 'catalog'
            io_indexes = []
            os_indexes = []

            aa = []
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
                                self.__error_list.append('exception: No pages entry')
                                print 'exception: Missing pages entry. Malformed PDF'
                                exit()

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
                                aa.append(pdf['Body'][j][cat_index][i]['Value']['AA']['Value'])
                        else:
                            self.__error_control('SpecViolation', 'Required \'Catalog\' entry missing.')

            return pages, names, outlines, openactions, acroforms, uris, aa


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
                        print 'Fix loop in __get_pagecount for indirect object trace'
                        exit()
            if omap['OS'].has_key(p_entry):
                index = omap['OS'][p_entry][-1:][0][0]
                if pdf['Body']['Object Streams'][index][p_entry]['Value'].has_key('Count'):
                    if pdf['Body']['Object Streams'][index][p_entry]['Value']['Count']['Value Type'] == 'Unknown':
                        pagecount = int(pdf['Body']['Object Streams'][index][p_entry]['Value']['Count']['Value'])
                    if pdf['Body']['Object Streams'][index][p_entry]['Value']['Count']['Value Type'] == 'Indirect Reference':
                        ir_index = pdf['Body']['Object Streams'][index][p_entry]['Value']['Count']['Value'].replace(' R', '')
                        print 'Fix loop in __get_pagecount for indirect object trace'
                        exit()
            if pagecount == None:
                print 'Page count is jacked.'
                exit()
            return pagecount


        def __process_pages(obj):
            def __process_annots(annots):
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

                    if a['Value Type'] == 'Dictionary':
                        if a['Value'].has_key('S'):
                            if a['Value']['S']['Value Type'] == 'Named Object':
                                sub_type.append(a['Value']['S']['Value'])
                        if a['Value'].has_key('URI'):
                            if a['Value']['URI']['Value Type'] == 'Literal String':
                                uri.append(a['Value']['URI']['Value'])

                    if a['Value Type'] == 'Indirect Reference':
                        a_ref = a['Value'].replace(' R', '')
                        a_map = self.__map_object(pdf['Body'], omap, a_ref, None, True)
                        processed_objects.append(a_ref)
                        for j in a_map:
                            for k in range(0, len(a_map[j])):
                                sub_type, uri = __get_hyperlink(a_map[j][k]['Value'])
                    return sub_type, uri


                if type(annots) == list:
                    for i in annots:
                        __process_annots(i)
                    return
                if annots.has_key('Value Type'):
                    if annots['Value Type'] == 'Indirect Reference':
                        IR = True
                        annots_ref = annots['Value'].replace(' R', '')
                        # Map it
                        if not annots_ref in processed_objects:
                            map_res = self.__map_object(pdf['Body'], omap, annots_ref, None, True)
                            processed_objects.append(annots_ref)
                            for i in map_res:
                                for j in range(0, len(map_res[i])):
                                    annots_index = map_res[i][j]['Index']
                                    annots_value = map_res[i][j]['Value']
                                    __process_annots(annots_value)
                        else:
                            return
                    else:
                        IR = False
                    if annots['Value Type'] == 'Dictionary':
                        __process_annots(annots['Value'])
                    if annots['Value Type'] == 'Array':
                        __process_annots(annots['Value'])
                        return
                if annots.has_key('Subtype'):
                    if annots['Subtype']['Value'] == 'Link' and annots.has_key('Rect'):
                        rect_area = []
                        __get_dimensions(annots['Rect'])
                        uri = []
                        sub_type = []

                        if not summary.has_key('Link Annotations'):
                            summary['Link Annotations'] = []

                        if annots.has_key('A'):
                            sub_type, uri = __get_hyperlink(annots['A'])


                        if len(uri) == 1 and len(sub_type) == 1 and len(rect_area) == 4:
                            summary['Link Annotations'].append({'Link': uri[0], 'Dimensions': rect_area})
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
                                        __process_annots(page_value['Annots'])
                                    if page_value.has_key('Kids'):
                                        __process_pages(page_value['Kids'])
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
                                    __process_annots(page_value['Annots'])
                                if page_value.has_key('Kids'):
                                    __process_pages(page_value['Kids'])
            return


        def __process_acroforms():
            # Get Fields entry. It's a required entry.
            acro_fields = []
            for i in acroforms:
                if i.has_key('Fields'):
                    for j in range(0, len(i['Fields']['Value'])):
                        af_val = i['Fields']['Value'][j]['Value'].replace(' R', '')
                        if not af_val in acro_fields:
                            acro_fields.append(af_val)

            if len(acro_fields) == 0:
                self.__error_control('SpecViolation', 'Acroform missing \'Fields\' entry.')

            # Process acro_fields. For now... I care about actions being executed.
            actions = []
            executing = []
            for i in acro_fields:
                processed_objects.append(i)
                acro_map = self.__map_object(pdf['Body'], omap, i, None, True)
                for j in acro_map:
                    for k in range(0, len(acro_map[j])):
                        acro_val = acro_map[j][k]['Value']
                        # Go check what kind entry we got there...
                        if acro_val['Value'].has_key('A'):
                            # Sweet action
                            if acro_val['Value']['A']['Value Type'] == 'Indirect Reference':
                                actions.append(acro_val['Value']['A']['Value'].replace(' R', ''))


            # Because these actions stemmed from an acroform we should be concerned with field 'F'
            if actions > 0:
                for i in actions:
                    processed_objects.append(i)
                    actions_map = self.__map_object(pdf['Body'], omap, i, None, True)
                    for j in actions_map:
                        for k in range(0, len(actions_map[j])):
                            val_ref = actions_map[j][k]['Value']
                            if val_ref['Value'].has_key('S'):
                                if val_ref['Value']['S']['Value'] in action_types.keys():
                                    subtype = val_ref['Value']['S']['Value']
                                    if subtype == 'SubmitForm':
                                        exec_key = val_ref['Value'][action_types[subtype]]['Value']['F']
                                        executing.append([subtype, exec_key['Value']])

            return executing


        def __process_names(names):
            def __process_embeddedfiles(embedded_files):
                embedded = []
                tmp_files = []
                if type(embedded_files) == dict:
                    if embedded_files.has_key('Value Type'):
                        if embedded_files['Value Type'] == 'Indirect Reference':
                            embedded.append(embedded_files['Value'].replace(' R', ''))
                if len(embedded) > 0:
                    for i in embedded:
                        if i in processed_objects:
                            continue
                        processed_objects.append(i)
                        ref_embedded = self.__map_object(pdf['Body'], omap, i, None, True)
                        for j in ref_embedded:
                            for k in range(0, len(ref_embedded[j])):
                                if ref_embedded[j][k]['Value']['Value'].has_key('Names'):
                                    if ref_embedded[j][k]['Value']['Value']['Names'].has_key('Value Type'):
                                        if ref_embedded[j][k]['Value']['Value']['Names']['Value Type'] == 'Array':
                                            for l in range(0, len(ref_embedded[j][k]['Value']['Value']['Names']['Value'])):
                                                if ref_embedded[j][k]['Value']['Value']['Names']['Value'][l]['Value Type'] == 'Literal String':
                                                    tmp_var = {}
                                                    tmp_var['Name'] = ref_embedded[j][k]['Value']['Value']['Names']['Value'][l]['Value']
                                                if ref_embedded[j][k]['Value']['Value']['Names']['Value'][l]['Value Type'] == 'Indirect Reference':
                                                    tmp_var['Location'] = ref_embedded[j][k]['Value']['Value']['Names']['Value'][l]['Value']
                                                    tmp_files.append(tmp_var)

                return tmp_files


            def __process_javascript(java_script):
                java = []
                tmp_java = []
                if type(java_script) == dict:
                    if java_script.has_key('Value Type'):
                        if java_script['Value Type'] == 'Indirect Reference':
                            java.append(java_script['Value'].replace(' R', ''))
                if len(java) > 0:
                    for i in java:
                        if i in processed_objects:
                            continue
                        processed_objects.append(i)
                        ref_java = self.__map_object(pdf['Body'], omap, i, None, True)
                        for j in ref_java:
                            for k in range(0, len(ref_java[j])):
                                if ref_java[j][k]['Value']['Value'].has_key('Names'):
                                    if ref_java[j][k]['Value']['Value']['Names'].has_key('Value Type'):
                                        if ref_java[j][k]['Value']['Value']['Names']['Value Type'] == 'Array':
                                            for l in range(0, len(ref_java[j][k]['Value']['Value']['Names']['Value'])):
                                                if ref_java[j][k]['Value']['Value']['Names']['Value'][l]['Value Type'] == 'Literal String':
                                                    tmp_var = {}
                                                    tmp_var['Name'] = ref_java[j][k]['Value']['Value']['Names']['Value'][l]['Value']
                                                if ref_java[j][k]['Value']['Value']['Names']['Value'][l]['Value Type'] == 'Indirect Reference':
                                                    tmp_var['Location'] = ref_java[j][k]['Value']['Value']['Names']['Value'][l]['Value']
                                                    tmp_java.append(tmp_var)
                return tmp_java

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
                    java = __process_javascript(names['JavaScript'])
                    for i in java:
                        name_javascript.append(i)
                if names.has_key('EmbeddedFiles'):
                    emb = __process_embeddedfiles(names['EmbeddedFiles'])
                    for i in emb:
                        name_files.append(i)

            #if type(names) == dict:
            return


        def __process_launch(obj):
            if obj.has_key('Win'): # 'F' key is mandatory
                if obj['Win']['Value'].has_key('F'):
                    if obj['Win']['Value']['F'].has_key('Value Type'):
                        if obj['Win']['Value']['F']['Value Type'] == 'Literal String':
                            win_app = obj['Win']['Value']['F']['Value']
                            launchie.append({'Win Exec': win_app})
            if obj.has_key('Mac'):
                print 'Mac execution object'
            if obj.has_key('Unix'):
                print 'Unix / Linux execution object'
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


        root_objects, xref_offsets = __find_root()
        try:
            pages, names, outlines, openactions, acroforms, uris, aa = __get_catalog_data()
        except Exception as e:
            raise e
        page_count = __get_pagecount()
        acro_count = len(acroforms)
        open_count = len(openactions)

        if acro_count > 0:
            a_actions = __process_acroforms()
        else:
            a_actions = []

        if page_count > 0: # Umm it better be...
            p_actions = __process_pages(pages)
        else:
            print 'Impossibru! There are no pages?!'
            exit()

        name_files, name_javascript = [], []
        if len(names) > 0:
            #name_tree = __process_names(names)
            __process_names(names)
        #else:
        #    name_tree = [[], []]

        js_checklist = (
            openactions,
            name_javascript
        )
        js = []
        launchie = []
        for i in js_checklist:
            __process_js(i)
        js_count = len(js)

        summary['Additional Actions'] = aa
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
                omap['XR Offsets'].append(pdf['XRef Tables'][i][0]['Offset'])

        return


    def __process_streams(self, x, bod):
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
                            cur_stream = self.__filter_parse(cur_stream, cur_filter, cur_decoder)
                        except SpecViolation as e:
                            self.__error_control(e.__repr__(), e.message, obj_name)
                        except Exception as e:
                            cur_error = 'Exception:', type(e), e, obj_name
                            self.__error_list.append(cur_error)

                if not cur_error == '':
                    bod['Indirect Objects'][i_object_index][obj_name]['Decoded Stream'] = cur_error
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
                            self.__error_list.append(cur_error)
                        if not cur_error == '':
                            bod['Indirect Objects'][i_object_index][obj_name]['Decoded Stream'] = cur_error
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
                            self.__error_list.append(cur_error)
                        if not cur_error == '':
                            bod['Indirect Objects'][i_object_index][obj_name]['Decoded Stream'] = cur_error
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
                stream_hash = self.__hash_stream(cur_stream)
                bod['Indirect Objects'][i_object_index][obj_name]['Stream Hashes'] = stream_hash
                if self.dump_streams:
                    dump_file = self.__gen_random_file()
                    open(self.dump_loc + dump_file, 'wb').write(cur_stream)
                    bod['Indirect Objects'][i_object_index][obj_name]['Stream Dump Location'] = self.dump_loc + dump_file
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


    def __filter_parse(self, my_stream, filter, decodeparms):
        ignore_filters = {
            'DCTDecode',
            'CCITTFaxDecode'
        }
        known_encoders = {
            'FlateDecode',
            'ASCIIHexDecode',
            'ASCII85Decode'
        }
        known_not_implemented = {
            'LZWDecode',
            'RunLengthDecode',
            'JBIG2Decode',
            'JPXDecode',
            'Crypt'
        }

        new_stream = my_stream

        if filter not in ignore_filters:
            if filter in known_not_implemented:
                return new_stream
            if filter in known_encoders:
                if filter == 'FlateDecode':
                    new_stream = self.__flatedecode(new_stream)
                if filter == 'ASCIIHexDecode':
                    new_stream = self.__asciihexdecode(new_stream)
                if filter == 'ASCII85Decode':
                    new_stream = self.__ascii85_decode(new_stream)
            else:
                raise SpecViolation("Invalid filter type passed to /Filter")
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

        if new_stream == '':
            print 'A decoder returned an empty string. Returning original data instead...'
            return my_stream
        else:
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


    def __flatedecode(self, i_buffer):
        data = zlib.decompress(i_buffer)

        return data


    def __decoder_tiff(self, my_stream):
        return my_stream


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


    def __body_scan(self, x, s_point):
        c = s_point
        l = len(x)
        mal_index = 0
        body = {}

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
                ret = self.__i_object_def_parse(x, c, 'trailer')
                c = ret[1]
                current_position = c
                # Check for obfuscation in named objects!
                try:
                    deob_ret = self.__named_object_deobfuscate(ret[0])
                except Exception as e:
                    self.__error_control(e.__repr__(), e.message, 'trailer: offset: ' + str(current_position))
                deob_ret['Offset'] = trailer_offset
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
                print '__i_object_parse:(Error: This is not an indirect object)'
        else:
            print '__i_object_parse:(Error: This is not an indirect object)'
        exit()


    def __update_mal_index(self, num, index):
        self.__overall_mal_index[index] += num
        if self.__overall_mal_index[index] > 255:
            self.__overall_mal_index[index] = 255
        return


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


        def __assemble_object_structure(datas, object_points, data_type = 'Value', eod = '', position = 0):
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

                    if p_type[0] == 'Hex':
                        k_type = 'Hexidecimal String'
                        k_val = datas[pos + 1:p_type[1]]
                        pos = p_type[1] + 1

                    if p_type[0] == 'String':
                        k_type = 'Literal String'
                        k_val = datas[pos + 1:p_type[1]]
                        pos = p_type[1] + 1

                    if p_type[0] == 'Dict':
                        k_type = 'Dictionary'
                        pos += 2
                        ret = __assemble_object_structure(datas, object_points, 'Dict', p_type[1] + 1, pos)
                        k_val = ret
                        pos = p_type[1] + 1

                    if p_type[0] == 'Array':
                        k_type = 'Array'
                        pos += 1
                        ret = __assemble_object_structure(datas, object_points, 'Array', p_type[1] + 1, pos)
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
                    p_type = point_type(object_points, pos)
                    if p_type[0] == None:
                        pos += 1

                    if p_type[0] == 'String':
                        v_type = 'Literal String'
                        v_val = datas[pos + 1:p_type[1]]
                        pos = p_type[1] + 1
                        key = True

                    if p_type[0] == 'Dict':
                        v_type = 'Dictionary'
                        pos += 2
                        ret = __assemble_object_structure(datas, object_points, 'Dict', p_type[1] + 1, pos)
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
                        v_val = datas[pos:p_type[1] + 1]
                        pos = p_type[1] + 1
                        key = True

                    if p_type[0] == 'Name':
                        v_type, v_val, pos = eval_name(datas[pos + 1:p_type[1] + 1], p_type[1])
                        key = True

                    if p_type[0] == 'Array':
                        v_type = 'Array'
                        pos += 1
                        ret = __assemble_object_structure(datas, object_points, 'Array', p_type[1] + 1, pos)
                        pos = p_type[1] + 1
                        v_val = ret
                        key = True

                    if pos >= end:
                        break

                if len(k_val) > 0 and len(v_val) > 0:
                    temp_dict[k_val] = {'Value Type': v_type, 'Value': v_val}

            if data_type == 'Dict':
                return temp_dict

            if data_type == 'Array':
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
                        try:
                            ret = deobfuscate(i)
                        except Exception as e:
                            raise SpecViolation('deobfuscate() failed.')
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


    def __header_scan(self, x):
        headers = {}

        # Checking for version header. Should be at offset 0x00
        h_loc = x.find('%', 0)
        if h_loc > 0:
            self.__error_control('SpecViolation', 'Arbitrary data before header')
        #if h_loc < 0:
        #    print 'Not a PDF. Exiting...'
        #    exit()
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
