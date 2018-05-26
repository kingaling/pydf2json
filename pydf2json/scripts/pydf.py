#!/usr/bin/env python
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

import pydf2json
import json
import argparse
import re


__version__ = ('2.1.16')
__author__ = ('Shane King <kingaling_at_meatchicken_dot_net>')


def argbuilder():
    parser = argparse.ArgumentParser(epilog="Note: Starred (*) arguments are disabled by default and will produce VERBOSE results if enabled.")
    parser.add_argument("pdf", help="Source PDF")
    parser.add_argument("-d", help="Dump all stream objects to a specified location", dest="location", metavar="LOCATION")
    parser.add_argument("-s", help="Set maximum size of file in megabytes. Default is 2.", dest="max_size", default = 2)
    parser.add_argument("-p", help="Specify PDF password", dest="password", metavar="PASSWORD")
    parser.add_argument("--no_summary",help="Showing the summary is the default. This disables it.", action="store_true")
    parser.add_argument("--show_json",help="Outputs pdf in json to the screen. Disabled by default.", action="store_true")
    jsongrp = parser.add_argument_group("json options")
    jsongrp.add_argument("--show_text", help="* Include page text in json output", action="store_true")
    jsongrp.add_argument("--show_ttf", help="* Include true type fonts in json output", action="store_true")
    jsongrp.add_argument("--show_bitmap", help="* Include bitmaps in json output", action="store_true")
    jsongrp.add_argument("--show_pics", help="* Include pictures in json output", action="store_true")
    jsongrp.add_argument("--show_embedded_files", help="* Include embedded files in json output", action="store_true")
    jsongrp.add_argument("--show_arbitrary", help="* Include arbitrary data in json output", action="store_true")
    jsongrp.add_argument("--show_all", help="* Include all streams including arbitrary data in json", action="store_true")
    args = parser.parse_args()
    return args


def main():
    args = argbuilder()
    pdf_object = pydf2json.PyDF2JSON()
    x = ""

    # Check if input file is valid
    if pydf2json.os.path.isfile(args.pdf):
        x = open(args.pdf, 'rb').read()
    else:
        print '%s does not exist.' % args.pdf
        exit()

    # Check if dump location was specified and is valid
    if not args.location == None:
        if pydf2json.os.path.isdir(args.location):
            pdf_object.dump_streams = True
            pdf_object.dump_loc = args.location
        else:
            print '%s is not a valid dump directory location.' % args.Location
            exit()

    # Check starred options:
    if args.show_bitmap or args.show_all:
        pdf_object.show_bitmaps = True
    if args.show_embedded_files or args.show_all:
        pdf_object.show_embedded_files = True
    if args.show_pics or args.show_all:
        pdf_object.show_pics = True
    if args.show_arbitrary or args.show_all:
        pdf_object.show_arbitrary = True
    if args.show_ttf or args.show_all:
        pdf_object.show_ttf = True
    if args.show_text or args.show_all:
        pdf_object.show_text = True

    # Check if a password was passed:
    if not args.password == None:
        pdf_object.pdf_password = args.password

    pdf_object.max_size = int(args.max_size)

    # JSON'ify the pdf! :)
    try:
        jsonpdf_tuple = pdf_object.GetPDF(x)
    except pydf2json.MaxSizeExceeded as e:
        print e
        print 'See command help for max_size override.'
        exit()
    except Exception as e:
        print e
        exit()

    #jsonpdf_tuple = pdf_object.GetPDF(x) # Debugging...
    jsonpdf = jsonpdf_tuple[0]
    omap = jsonpdf_tuple[1]
    summary = jsonpdf_tuple[2]
    del jsonpdf_tuple

    if re.match('exception', str(jsonpdf)):
        print jsonpdf
        exit()

    if args.show_json:
        print json.dumps(jsonpdf, ensure_ascii=False, indent=4)

    if not args.no_summary:
        # Parse summary for presentation...
        print 'Summary of PDF attributes:'
        print '--------------------------\n'
        if summary['Encryption']['enabled']:
            print '{:<29} {:<32}'.format('Encrypted:', 'True')
            print '{:<29} {:<32}'.format('Key:', summary['Encryption']['file_key'])
            print '{:<29} {:<32}'.format('Key Length:', summary['Encryption']['key_length'])
            print '{:<29} {:<32}\n'.format('Algo:', summary['Encryption']['algorithm'])
        else:
            print '{:<20} {:>10}'.format('Encrypted:', 'False')
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

        #print '{:<20} {:>10}'.format('AA:', str(len(summary['Additional Actions'])))
        print '{:<20} {:>10}'.format('Additional Actions:', str(aa_num))
        print '{:<20} {:>10}'.format('AcroForms:', str(summary['AcroForms']))
        print '{:<20} {:>10}'.format('Embedded Files:', str(len(summary['EmbeddedFiles'])))
        print '{:<20} {:>10}'.format('JS:', summary['JS'])
        print '{:<20} {:>10}'.format('Launch:', str(len(summary['Launch'])))
        print '{:<20} {:>10}'.format('Object Streams:', str(summary['Object Streams']))
        print '{:<20} {:>10}'.format('OpenActions:', str(summary['OpenActions']))
        print '{:<10} {:>20}'.format('Pages:', str(summary['Pages']))

        if len(summary['Arbitrary Data']) > 0:
            print '\nArbitrary data detected (data outside any known PDF object)'
            for i in summary['Arbitrary Data']:
                print '\t' + str(i)

        if len(summary['AcroForm Actions']) > 0:
            print '\nAcroForm Actions'
            for i in summary['AcroForm Actions']:
                print '\t' + str(i)

        if len(summary['Launch']) > 0:
            print '\nLaunches detected:'
            for i in summary['Launch']:
                print '\t' + str(i)

        if len(summary['Names']) > 0:
            print '\nName Tree trace entries:'
            if len(summary['EmbeddedFiles']) > 0:
                print '\tEmbeddedFiles'
                for i in summary['EmbeddedFiles']:
                    print '\t\t' + str(i)
            if len(summary['JavaScript']) > 0:
                print '\n\tJavaScript'
                for i in summary['JavaScript']:
                    print '\t\t' + str(i)

        if summary.has_key('Link Annotations'):
            if len(summary['Link Annotations']) > 0:
                print '\nURIs in document:'
                tmp_link = []
                for i in summary['Link Annotations']:
                    for j in summary['Link Annotations'][i]:
                        if not j['Link'] in tmp_link:
                            tmp_link.append(j['Link'])
                for i in tmp_link:
                    print '\t' + i
            else:
                print '{:<21} {:>10}'.format('\nURIs in document:', '0')

        if aa_num > 0:
            print '\nAdditional Actions (AA) detected:'
            for i in aa_sections:
                if i == 'acro_adds':
                    print '\tAcroform Fields AA:'
                if i == 'annot_adds':
                    print '\tAnnotations AA:'
                if i == 'page_adds':
                    print '\tPage AA:'
                if i == 'cat_adds':
                    print '\tCatalog AA:'
                for j in aa_sections[i]:
                        print '\t\t', j

        print '\nDocument Hashes:'
        for i in jsonpdf['Document Hashes']:
            print '\t{:<10} {:<0}'.format(i, jsonpdf['Document Hashes'][i])
if __name__ == '__main__':
    main()