import hashlib
import struct
import sys
try:
    # noinspection PyPackageRequirements
    from Crypto.Cipher import AES
except Exception as e:
    pass


class PDFCrypto(object):

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

    def retreive_file_key(self, handler_info, pdf_password):
        # Generate file_key based on Version/Revision
        if handler_info['version'] < 5:
            # Blank password padding used by Adobe...
            pad = '28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A'

            if pdf_password is None:
                pdf_pass = pad
            else:
                tmp_pass = pdf_password.encode('hex').upper()
                lex = len(tmp_pass)
                if lex < 64:
                    short = 64 - lex
                    temp_pass = tmp_pass + pad[0:short]
                else:
                    temp_pass = tmp_pass[0:64]
                pdf_pass = temp_pass

            file_key = self.gen_file_key(handler_info, pdf_pass)

            # Test if file key is valid
            u_check = self.confirm_file_key(handler_info, pad, file_key)
            if u_check[0:16] == handler_info['U'][0:32].decode('hex'):
                handler_info['file_key'] = file_key
            else:
                raise Exception('Encrypted document requires a password. Aborting analysis.')

        if handler_info['version'] == 5:
            # Blank password padding used by Adobe is NOT used for AESV3.
            # Instead, set it to an empty string.
            if pdf_password is None:
                pdf_pass = ''
            else:
                pdf_pass = pdf_password

            if not 'Crypto.Cipher.AES' in sys.modules:
                raise Exception('Missing pycrypto. pip install pycrypto')

            file_key, perms = self.func_2A(pdf_pass,
                                                  handler_info['O'].decode('hex'),
                                                  handler_info['U'].decode('hex'),
                                                  handler_info['OE'].decode('hex'),
                                                  handler_info['UE'].decode('hex'),
                                                  handler_info['Perms'].decode('hex'),
                                                  handler_info['P'])
            handler_info['file_key'] = file_key
            handler_info['file_perms'] = perms

    def gen_file_key(self, handler, password):
        md = hashlib.md5()
        md.update(password.decode('hex'))  # Input should have been hex string
        md.update(handler['O'].decode('hex'))  # Input should have been hex string
        md.update(handler['P'])                # Input should have already been decoded into hex value
        md.update(handler['doc_id'].decode('hex')) # Input should have been hex string
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

    def confirm_file_key(self, handler, password, file_key):
        md = hashlib.md5()
        if handler['revision'] >= 3:
            md.update(password.decode('hex'))
            md.update(handler['doc_id'].decode('hex'))

            digest = md.digest()

            cipher = self.rc4_crypt(digest, file_key)

            for i in range(0, 19):
                key = ''

                for j in file_key:
                    key += (chr(ord(j) ^ (i + 1)))

                cipher = self.rc4_crypt(cipher, key)
        else:
            cipher = self.rc4_crypt(password.decode('hex'), file_key)
            return cipher

        return cipher

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

    def decrypt(self, handler, x, data_type, cur_obj, hndlr = None):
        data_is_crypted = False # May seem redundant but it's not. Global encryption may be in effcet but this piece of data may not be encrypted.

        if data_type == 'Literal String':
            if handler['version'] == 4 or handler['version'] == 5:
                if handler['StrF'] == 'StdCF': # Assume string is encrypted with standard handler
                    data_is_crypted = True
                    new_str = self.escaped_string_replacement(x)
                else:
                    # Assume string is not encrypted and return decoded hex value
                    return x.decode('hex')
            if handler['version'] <= 3:
                data_is_crypted = True
                new_str = self.escaped_string_replacement(x)
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

    def func_2A(self, password, o, u, oe, ue, Perms, P):
        def __get_filekey(password, o, u, oe, ue, check_type):
            U = u[0:48]
            u_hash = u[0:32]
            uv_salt = u[32:40]
            uk_salt = u[40:48]
            o_hash = o[0:32]
            ov_salt = o[32:40]
            ok_salt = o[40:48]

            IV = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            found = False

            if check_type == 'owner':
                check = self.func_2B(password + ov_salt + U, password, U, purpose='O_CHECK')
            if check_type == 'user':
                check = self.func_2B(password + uv_salt, password, U, purpose='U_CHECK')

            if check == o_hash:
                # Owners password was used
                key = self.func_2B(password + ok_salt + U, password, U, purpose='O_CREATE')
                file_key = self.aes_crypt(oe, key, AES.MODE_CBC, IV, padding=False, function='decrypt')
                found = True

            if check == u_hash:
                # Users password was used
                key = self.func_2B(password + uk_salt, password, U, purpose='U_CREATE')
                file_key = self.aes_crypt(ue, key, AES.MODE_CBC, IV, padding=False, function='decrypt')
                found = True

            if found:
                return file_key
            else:
                return

        # Check if this is the owners pass or users pass:
        file_key =__get_filekey(password, o, u, oe, ue, check_type='owner')
        if file_key == None:
            file_key =__get_filekey(password, o, u, oe, ue, check_type='user')
            if file_key == None:
                raise Exception('Unable to decrypt document. Bad password?')


        IV = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        perms = self.aes_crypt(Perms, file_key, AES.MODE_ECB, IV, padding=False, function='decrypt')

        if P[0:4] == perms[0:4] and perms[9:12] == 'adb':
            return file_key, perms
        else:
            raise Exception('SpecViolation: Perms string is non compliant.')

    def func_2B(self, input, password, h_salts, purpose):
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

