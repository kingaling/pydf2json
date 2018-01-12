#!/usr/bin/env python

import pydf2json
import json
import argparse
import re


__version__ = ('2.1.4')
__author__ = ('Shane King <kingaling_at_meatchicken_dot_net>')


def argbuilder():
    parser = argparse.ArgumentParser(epilog="Note: Starred (*) arguments are disabled by default and will produce VERBOSE results if enabled.")
    parser.add_argument("pdf", help="Source PDF")
    parser.add_argument("-d", help="Dump all stream objects to a specified location", dest="location", metavar="LOCATION")
    parser.add_argument("--no_summary",help="Showing the summary is the default. This disables it.", action="store_true")
    parser.add_argument("--show_json",help="Outputs pdf in json to the screen. Disabled by default.", action="store_true")
    parser.add_argument("--show_ttf", help="* Include true type fonts in json output", action="store_true")
    parser.add_argument("--show_bitmap", help="* Include bitmaps in json output", action="store_true")
    parser.add_argument("--show_pics", help="* Include pictures in json output", action="store_true")
    parser.add_argument("--show_embedded_files", help="* Include embedded files in json output", action="store_true")
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
    if args.show_bitmap:
        pdf_object.show_bitmaps = True
    if args.show_embedded_files:
        pdf_object.show_embedded_files = True
    if args.show_pics:
        pdf_object.show_pics = True
    if args.show_ttf:
        pdf_object.show_ttf = True

    # JSON'ify the pdf! :)
    try:
        jsonpdf_tuple = pdf_object.GetPDF(x)
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

    # Things I gotta do:
    # Error checking everywhere

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
        print '{:<20} {:>10}'.format('AA:', str(len(summary['Additional Actions'])))
        print '{:<20} {:>10}'.format('AcroForms:', str(summary['AcroForms']))
        print '{:<20} {:>10}'.format('Embedded Files:', str(len(summary['EmbeddedFiles'])))
        print '{:<20} {:>10}'.format('JS:', summary['JS'])
        print '{:<20} {:>10}'.format('Launch:', str(len(summary['Launch'])))
        print '{:<20} {:>10}'.format('Object Streams:', str(summary['Object Streams']))
        print '{:<20} {:>10}'.format('OpenActions:', str(summary['OpenActions']))
        print '{:<10} {:>20}'.format('Pages:', str(summary['Pages']))

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
                print '\n\t\tWarning: Document level JavaScript entries are equivalent to an OpenAction!'

        if summary.has_key('Link Annotations'):
            if len(summary['Link Annotations']) > 0:
                print '\nURIs in document:'
                tmp_link = []
                for i in summary['Link Annotations']:
                    if not i['Link'] in tmp_link:
                        tmp_link.append(i['Link'])
                for i in tmp_link:
                    print '\t' + i
            else:
                print '{:<21} {:>10}'.format('\nURIs in document:', '0')

        print '\nDocument Hashes:'
        for i in jsonpdf['Document Hashes']:
            print '\t{:<10} {:<0}'.format(i, jsonpdf['Document Hashes'][i])
if __name__ == '__main__':
    main()