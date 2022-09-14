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
import argparse
import os


__version__ = '1.0.2'
__author__ = 'Shane King <kingaling_at_meatchicken_dot_net>'


def argbuilder():
    parser = argparse.ArgumentParser(epilog="Note: This code is for obtaining the open/user password, not the owner password.")
    parser.add_argument("pdf", help="Source PDF")
    parser.add_argument("--min", help="Minimum password length. Default = 1", dest="min", metavar="min", default=1, type=int)
    parser.add_argument("--max", help="Maximum password length. Default = 4", dest="max", metavar="max", default=4, type=int)
    parser.add_argument("-c", help="Specify charsets. Defaults to digits. Comma separated, no space:\nu = upper case;\nl = lower case;\
    \nd = digits;\np = punctuation", dest="charset", metavar="charset", default="d")

    args = parser.parse_args()
    return args


def gen_charset(sets):
    lower = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
             'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

    upper = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
             'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']

    nums = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

    punc = ['~', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')',
            '_', '+', '{', '}', ':', '\"', '<', '>', '?', '`', '-',
            '=', '[', ']', ';', '\'', ',', '.', '/', '|', '\\']

    chars = []
    for i in sets.split(','):
        if i == 'd':
            chars += nums
        if i == 'l':
            chars += lower
        if i == 'u':
            chars += upper
        if i == 'p':
            chars += punc

    return chars


def crack(handler, target, min, max, chars):
    def target_type_1(password):
        if crypto.authv6_U(password, handler['U']):
            return True
        return False
    def target_type_2(password):
        tmpU_key = crypto.genv4r2_U_entry(handler, password)
        if tmpU_key == handler['U']:
            return True
        return False
    def target_type_3(password):
        tmpU_key = crypto.genv4r34_U_entry(handler, password)
        if tmpU_key == handler['U']:
            return True
        return False


    crypto = pydf2json.PDFCrypto()
    base = len(chars)
    password = [chars[0]] * (min - 1)
    start = 0
    rollover_index = min - 2
    threshhold = base ** (len(password) + 1)
    while True:
        for i in chars:
            tmp_pass = ''.join(password) + i
            start += 1
            if target == 1: res = target_type_1(tmp_pass)
            if target == 2: res = target_type_2(tmp_pass)
            if target == 3: res = target_type_3(tmp_pass)
            if res: return tmp_pass
        if start == threshhold:
            if len(tmp_pass) == max:
                return False
            start = 0
            password.insert(0, chars[0])
            threshhold = base ** (len(password) + 1)
            for j in range(0, len(password)):
                password[j] = chars[0]
            rollover_index = len(password) - 1
            continue
        while True:
            if password[rollover_index] == chars[base-1]:
                rollover_index -= 1
                continue
            else:
                password[rollover_index] = chars[chars.index(password[rollover_index]) + 1]
                for j in range(rollover_index + 1, len(password)):
                    password[j] = chars[0]
                rollover_index = len(password) - 1
                break


def main():
    args = argbuilder()

    # Check if input file is valid
    if os.path.isfile(args.pdf):
        x = open(args.pdf, 'rb').read()
    else:
        print '%s does not exist.' % args.pdf
        exit()

    pdfobj = pydf2json.PyDF2JSON()
    try:
        handler = pdfobj.get_encryption_handler(x)
    except Exception as e:
        print e
        exit()

    if handler == None:
        print "PDF has no encryption handler."
        exit()

    # Parse handler stuff
    if handler['version'] == 5:
        target_type = 1
    if handler['version'] < 5 and handler['revision'] < 3:
        target_type = 2
    if handler['version'] < 5 and handler['revision'] >= 3:
        target_type = 3

    charset = gen_charset(args.charset)
    crackres = crack(handler, target_type, args.min, args.max, charset)

    return crackres


def cl():
    # Called if executed from command line.
    # Also serves as command line execution when being called from an exe if you
    # installed this as a package with pip.
    print 'Attempting crack...'
    result = main()
    if result: print 'Password: ' + result
    else: print 'Failed'


if __name__ == '__main__':
    cl()
