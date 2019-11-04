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

import hashlib
import struct
import random
try:
    # noinspection PyPackageRequirements
    from Crypto.Cipher import AES
except Exception as e:
    pass


class PDFCrypto(object):
    # Adobe password padding for encryption handlers version <= 4
    pad = '28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A'.decode('hex')

    # Binary values stored in handler entries may be escaped (or need to be escaped if you're creating the values)
    # The following 2 function are just for that.
    def escaped_string_replacement(self, x):
        new_str = ''
        skip = False
        for i in range(0, len(x), ++2):
            if skip:
                skip = False
                continue
            tmp = x[i:i + 2]
            if tmp == '5c':
                esc_seq = tmp + x[i + 2:i + 4]
                if esc_seq == '5c6e': # \n
                    new_str += '0a'
                    skip = True
                if esc_seq == '5c72': # \r
                    new_str += '0d'
                    skip = True
                if esc_seq == '5c74': # \t
                    new_str += '09'
                    skip = True
                if esc_seq == '5c62': # \b
                    new_str += '08'
                    skip = True
                if esc_seq == '5c66': # \f
                    new_str += '0c'
                    skip = True
                if esc_seq == '5c28': # \(
                    new_str += '28'
                    skip = True
                if esc_seq == '5c29': # \)
                    new_str += '29'
                    skip = True
                if esc_seq == '5c5c': # \\
                    new_str += '5c'
                    skip = True
            else:
                new_str += tmp
        return new_str

    def escaped_string_insertion(self, x):
        new_str = ''
        for i in range(0, len(x), ++2):
            tmp = x[i:i + 2]
            if tmp == '5c' or tmp == '0d' or tmp == '0a' or \
                    tmp == '08' or tmp == '28' or tmp == '29':
                new_str += ('5c' + tmp)
            else:
                new_str += tmp
        return new_str

    # Called during decryption of PDF objects. Returns object decryption key.
    def gen_obj_key(self, f_key, key_size, method, obj):
        obj = obj.split()
        key_size /= 8
        o_num = struct.pack('<L', int(obj[0]))[:3]
        o_gen = struct.pack('<L', int(obj[1]))[:2]
        salt = struct.pack('>L', 0x73416C54)
        md = hashlib.md5()
        md.update(f_key)
        md.update(o_num)
        md.update(o_gen)
        if method == 'AESV2':
            md.update(salt)

        o_key = md.digest()
        f_key_size = key_size + 5
        if f_key_size > 16:
            f_key_size = f_key_size - (f_key_size % 16)

        return o_key[0:f_key_size]

    def rc4_crypt(self, data, key ):
        S = range(256)
        j = 0
        out = []

        #KSA Phase
        for i in range(256):
            j = (j + S[i] + ord( key[i % len(key)] )) % 256
            S[i] , S[j] = S[j] , S[i]

        #PRGA Phase
        i = j = 0
        for char in data:
            i = ( i + 1 ) % 256
            j = ( j + S[i] ) % 256
            S[i] , S[j] = S[j] , S[i]
            out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))

        return ''.join(out)

    def decrypt(self, handler, x, data_type, cur_obj, escape=True, hndlr = None):
        data_is_crypted = False # May seem redundant but it's not. Global encryption may be in effcet but this piece of data may not be encrypted.

        if data_type == 'Literal String':
            if handler['version'] == 4 or handler['version'] == 5:
                if handler['StrF'] == 'StdCF': # Assume string is encrypted with standard handler
                    data_is_crypted = True
                    if escape: new_str = self.escaped_string_replacement(x)
                    else: new_str = x
                else:
                    # Assume string is not encrypted and return decoded hex value
                    return x.decode('hex')
            if handler['version'] <= 3:
                data_is_crypted = True
                if escape: new_str = self.escaped_string_replacement(x)
                else: new_str = x
        else:
            new_str = x

        if data_type == 'stream':
            if handler['version'] == 4 or handler['version'] == 5:
                if handler['StmF'] == 'StdCF' or hndlr == 'StdCF': # Assume stream is encrypted with standard handler
                    data_is_crypted = True
                else:
                    return x
            if handler['version'] <= 3:
                data_is_crypted = True

        if data_is_crypted:
            if handler['method'] == 'AESV2':
                if data_type == 'Literal String':
                    IV = new_str[0:32].decode('hex')
                if data_type == 'stream':
                    IV = new_str[0:16]

                if data_type == 'Literal String':
                    new_str = self.aes_crypt(new_str[32:].decode('hex'), handler['o_keys'][cur_obj],
                                               AES.MODE_CBC, IV, padding=False, function='decrypt')
                if data_type == 'stream':
                    if hndlr == 'StdCF':
                        new_str = self.aes_crypt(new_str[16:], handler['file_key'],
                                                   AES.MODE_CBC, IV, padding=False, function='decrypt')
                    if hndlr == None:
                        new_str = self.aes_crypt(new_str[16:], handler['o_keys'][cur_obj],
                                                   AES.MODE_CBC, IV, padding=False, function='decrypt')

                # Remove RFC 2898 padding
                pad = ord(new_str[-1:])
                new_str = new_str[:-pad]
                return new_str

            if handler['method'] == 'AESV3':
                if data_type == 'Literal String':
                    IV = new_str[0:32].decode('hex')
                if data_type == 'stream':
                    IV = new_str[0:16]

                if data_type == 'Literal String':
                    new_str = self.aes_crypt(new_str[32:].decode('hex'), handler['file_key'],
                                               AES.MODE_CBC, IV, padding=False, function='decrypt')
                if data_type == 'stream':
                    new_str = self.aes_crypt(new_str[16:], handler['file_key'], AES.MODE_CBC, IV,
                                               padding=False, function='decrypt')
                return new_str

            if handler['method'] == 'V2' or handler['method'] == 'RC4':
                if data_type == 'Literal String':
                    new_str = self.rc4_crypt(new_str.decode('hex'), handler['o_keys'][cur_obj])
                if data_type == 'stream':
                    new_str = self.rc4_crypt(new_str, handler['o_keys'][cur_obj])
                return new_str

        return new_str

    def aes_crypt(self, plaintext, key, mode, iv, padding, function):
        pad = len(plaintext) % 16
        if pad == 0:
            pad += 16
        else:
            pad = 16 - pad
        padstr = ''
        if padding:
            for i in range(pad):
                padstr += chr(pad)
        else:
            for i in range(pad):
                padstr += '\x00'
        plaintext += padstr

        cryptor = AES.new(key, mode, iv)
        if function == 'encrypt':
            E = cryptor.encrypt(plaintext)
        if function == 'decrypt':
            E = cryptor.decrypt(plaintext)

        if not padding:
            return E[0:-pad]
        else:
            return E

    ## File Encryption Key Algorithms
    # Algo 2. Gen file key for version <= 4
    def retrv4_fkey(self, handler, pdf_password):
        pdf_pass = (pdf_password + self.pad)[0:32]
        md = hashlib.md5()
        md.update(pdf_pass)
        md.update(handler['O'])
        md.update(struct.pack('<l', int(handler['P'])))
        md.update(handler['doc_id'])
        key_size = handler['key_length'] / 8
        if handler['version'] == 4:
            if not handler['encrypt_metadata']:
                md.update('\xff\xff\xff\xff')
        f_key = md.digest()

        if handler['revision'] >= 3:
            for i in range(0, 50):
                md = hashlib.md5()
                md.update(f_key[0:key_size])
                f_key = md.digest()

        f_key = f_key[0:key_size]

        return f_key

    # Algo 2.A. Revision 6. Retrieve file encryption key
    def retrv5_fkey(self, handler, password, pass_type):
        U = handler['U'][0:48]
        O = handler['O'][0:48]
        uk_salt = U[40:48]
        ok_salt = O[40:48]
        UE = handler['UE']
        OE = handler['OE']
        IV = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

        # step a and b are already done. Password should be normalized prior to calling this.
        # For step c:
        # Test the password before calling this function with algorithm 11 or 12

        # step d
        if pass_type == 'Owner':
            key = self.genv6_hash(password + ok_salt + U, password, U, purpose='O_CREATE')
            file_key = self.aes_crypt(OE, key, AES.MODE_CBC, IV, padding=False, function='decrypt')
            return file_key

        # step e
        if pass_type == 'User':
            key = self.genv6_hash(password + uk_salt, password, None, purpose='U_CREATE')
            file_key = self.aes_crypt(UE, key, AES.MODE_CBC, IV, padding=False, function='decrypt')
            return file_key

    # Algo 2.B. Revision 6. Compute hash
    def genv6_hash(self, input, password, h_salts, purpose):
        md = hashlib.sha256()
        md.update(input)
        K = md.digest()

        round = 0
        while True:
            round +=1

            K1 = ''
            for i in range(64):
                if purpose == 'O_CHECK' or purpose == 'O_CREATE':
                    K1 += password + K + h_salts # h_salts should equal a 48-byte U string; hash + v & k salts
                else:
                    K1 += password + K

            key = K[0:16]
            IV = K[16:32]
            E = self.aes_crypt(K1, key, AES.MODE_CBC, IV, padding=False, function='encrypt')

            tmp_int = int(E[0:16].encode('hex'), 16)
            modulus = tmp_int % 3
            if modulus == 0:
                md = hashlib.sha256()
            if modulus == 1:
                md = hashlib.sha384()
            if modulus == 2:
                md = hashlib.sha512()
            md.update(E)
            K = md.digest()
            last_E = ord(E[-1:])
            if round >= 64 and last_E <= ((round - 1) - 32):
                break

        return K[0:32]

    ## Password Algorithms
    # Algo 3. <= V4. Calculate O entry.
    def genv4_O_entry(self, handler, o_password, u_password, caller=None):
        # step a
        if o_password == '':
            hash_pass = (u_password + self.pad)[0:32]
        else:
            hash_pass = (o_password + self.pad)[0:32]

        # step b
        md = hashlib.md5()
        md.update(hash_pass)
        K = md.digest()
        key_size = 5

        if handler['revision'] >= 3:
            key_size = handler['key_length'] / 8 # key_size different for revision > 2
            # step c
            for i in range(0, 50):
                md = hashlib.md5()
                md.update(K)
                K = md.digest()

        # Step d
        f_key = K[0:key_size]
        if caller == 'A7': # Was this function called by algorithm 7?
            return f_key

        # step e
        hash_pass = (u_password + self.pad)[0:32]

        # Step f
        cipher = self.rc4_crypt(hash_pass, f_key)

        # step g
        if handler['revision'] >= 3:
            for i in range(0, 19):
                key = ''
                for j in f_key:
                    key += (chr(ord(j) ^ (i + 1)))
                cipher = self.rc4_crypt(cipher, key)

        return cipher

    # Algo 4. Revision 2. Calculate U entry.
    def genv4r2_U_entry(self, handler, u_password):
        # step a
        file_key = self.retrv4_fkey(handler, u_password)

        # step b
        u_entry = self.rc4_crypt(self.pad, file_key)

        # step c. Store value as U entry. I am simply returning the value for now.
        # Because I am only returning the value, this function doubles as Algo 6.
        return u_entry

    # Algo 5. Revision 3 & 4. Calculate U entry.
    def genv4r34_U_entry(self, handler, u_password):
        # step a
        file_key = self.retrv4_fkey(handler, u_password)

        # step b
        md = hashlib.md5()
        md.update(self.pad)

        # step c
        md.update(handler['doc_id'])
        md5 = md.digest()

        # step d
        cipher = self.rc4_crypt(md5, file_key)

        # step e
        for i in range(0, 19):
            key = ''
            for j in file_key:
                key += (chr(ord(j) ^ (i + 1)))
            cipher = self.rc4_crypt(cipher, key)

        # step f.
        cipher += '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

        # Store value as U entry. I am simply returning the value for now.
        # Because I am only returning the value, this function doubles as Algo 6.
        return cipher

    # Algo 6. Revision <= 4. Auth user password.
    # See the tail ends of algo 4 and 5 :)

    # Algo 7. Revision <= 4. Auth owner password.
    def authv4_O(self, handler, o_password):
        # step a
        u_password = ''
        f_key = self.genv4_O_entry(handler, o_password, u_password, 'A7')

        # step b
        if handler['revision'] < 3:
            u_password = self.rc4_crypt(handler['O'], f_key) # this = user password + padding
            return u_password

        if handler['revision'] >= 3:
            plaintext = handler['O']
            for i in range(20, 0, -1):
                key = ''
                for j in f_key:
                    key += (chr(ord(j) ^ (i - 1)))
                plaintext = self.rc4_crypt(plaintext, key) # The final iteration returns 32 byte user password + padding

            u_password = self.genv4r34_U_entry(handler, plaintext)

        # step c
        if u_password[0:16] == handler['U'][0:16]:
            return plaintext # return 32 byte padded user password
        return ''

    # Note: For algorithms 8 to 13, the file encryption key shall be a 256-bit (32-byte)
    # value generated with a strong random number generator.

    # Algo 8. Revision 6. Calc U and UE
    def genv6_U_UE(self, u_password, file_key):
        # initialize needful things
        chars = ''
        IV = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

        for i in range(0,256):
            chars += chr(i)

        # step a
        tmp = "".join(random.sample(chars, 16))
        U = self.genv6_hash(u_password + tmp[0:8], u_password, None, 'U_CREATE')
        U += tmp

        # step b
        key = self.genv6_hash(u_password + tmp[8:16], u_password, None, 'U_CREATE')
        UE = self.aes_crypt(file_key, key, AES.MODE_CBC, IV, padding=False, function='encrypt')

        return U, UE

    # Algo 9. Revision 6. Calc O and OE
    def genv6_O_OE(self, o_password, file_key, U):
        # initialize needful things
        chars = ''
        IV = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

        for i in range(0,256):
            chars += chr(i)

        # step a
        tmp = "".join(random.sample(chars, 16))
        O = self.genv6_hash(o_password + tmp[0:8] + U, o_password, U, 'O_CREATE')
        O += tmp

        # step b
        key = self.genv6_hash(o_password + tmp[8:16] + U, o_password, U, 'O_CREATE')
        OE = self.aes_crypt(file_key, key, AES.MODE_CBC, IV, padding=False, function='encrypt')

        return O, OE

    # Algo 10. Revision 6. Calc Perms
    def genv6_Perms(self, file_key, meta_bool, perms):
        # initialize needful things
        chars = ''
        IV = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

        for i in range(0, 4):
            chars += chr(i)

        # step a and b
        P = struct.pack('<l', perms) + '\xFF\xFF\xFF\xFF'

        # step c
        if meta_bool:
            P += 'T'
        else:
            P += 'F'

        # step d and e
        P += 'adb' + chars

        # step f
        Perms = self.aes_crypt(P, file_key, AES.MODE_CBC, IV, padding=False, function='encrypt')

        return Perms

    # Algo 11. Revision 6. Auth user password
    def authv6_U(self, u_password, U):
        uv_salt = U[32:40]
        if self.genv6_hash(u_password + uv_salt, u_password, None, 'U_CHECK') == U[0:32]:
            return True
        return False

    # Algo 12. Revision 6. Auth owner password
    def authv6_O(self, o_password, O, U):
        ov_salt = O[32:40]
        if self.genv6_hash(o_password + ov_salt + U[0:48], o_password, U[0:48], 'O_CHECK') == O[0:32]:
            return True
        return False

    # Algo 13. Revision 6. Validate perms
    def authv6_Perms(self, P, Perms, file_key):
        IV = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

        P = struct.pack('<l', int(P))
        perms = self.aes_crypt(Perms, file_key, AES.MODE_ECB, IV, padding=False, function='decrypt')

        if P[0:4] == perms[0:4] and perms[9:12] == 'adb':
            return True
        return False
