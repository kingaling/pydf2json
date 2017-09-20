import pydf2json
import json
import argparse
import re

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
        jsonpdf = pdf_object.GetPDF(x)
    except:
        print 'Unhandled exception. Aborting analysis.'
        exit()
    # jsonpdf = pdf_object.GetPDF(x) # Debugging...

    if re.match('exception', str(jsonpdf)):
        print jsonpdf
        exit()

    if args.show_json:
        print json.dumps(jsonpdf, ensure_ascii=False, indent=4)

    # Things I gotta do:
    # Error checking everywhere
    # Create command line summary

    if not args.no_summary:
        # Parse summary for presentation...
        print 'Summary of PDF attributes:'
        print '--------------------------\n'
        print '{:<20} {:>10}'.format('AA:', str(len(jsonpdf['Summary']['AA'])))
        print '{:<20} {:>10}'.format('AcroForms:', str(len(jsonpdf['Summary']['AcroForm'])))
        print '{:<20} {:>10}'.format('Embedded Files:', str(len(jsonpdf['Summary']['Embedded Files'])))
        if len(jsonpdf['Summary']['JS']) == 0:
            print '{:<20} {:>10}'.format('JS:', '0')
        else:
            jscount = 0
            for i in range(0, len(jsonpdf['Summary']['JS'])):
                for j in jsonpdf['Summary']['JS'][i]:
                    if not type(jsonpdf['Summary']['JS'][i][j]) == dict:
                        jscount += 1
                    else: # Looks like we got JS in an object stream. Do it...
                        for k in jsonpdf['Summary']['JS'][i][j]:
                            jscount += 1
            print '{:<10} {:>20}'.format('JS:', str(jscount))
        print '{:<20} {:>10}'.format('Launch:', str(len(jsonpdf['Summary']['Launch'])))
        print '{:<20} {:>10}'.format('Object Streams:', str(len(jsonpdf['Summary']['Object Streams'])))
        print '{:<20} {:>10}'.format('OpenActions:', str(len(jsonpdf['Summary']['OpenAction'])))
        print '{:<10} {:>20}'.format('Pages:', str(jsonpdf['Summary']['Page Count']))

        if len(jsonpdf['Summary']['Names']) > 0:
            print '\nName Tree trace entries:'
            if len(jsonpdf['Summary']['EmbeddedFiles']) > 0:
                print '\tEmbeddedFiles'
            if len(jsonpdf['Summary']['JavaScript']) > 0:
                print '\tJavaScript'

        if len(jsonpdf['Summary']['URI List']) == 0:
            print '{:<21} {:>10}'.format('\nURIs in document:', '0')
        else:
            print '\nURIs in document:'
            for i in range(0, len(jsonpdf['Summary']['URI List'])):
                for j in jsonpdf['Summary']['URI List'][i]:
                    if not type(jsonpdf['Summary']['URI List'][i][j]) == dict:
                        print '  O: ' + j + '\t' + jsonpdf['Summary']['URI List'][i][j]
                    else: # Looks like we got URIs in an object stream. Do it...
                        for k in jsonpdf['Summary']['URI List'][i][j]:
                            print '  OS: ' + j + '\t' + 'O: ' + k + '\t\t' + jsonpdf['Summary']['URI List'][i][j][k]


if __name__ == '__main__':
    main()