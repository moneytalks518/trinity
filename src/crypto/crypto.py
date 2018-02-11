"""Author: Trinity Core Team

MIT License

Copyright (c) 2018 Trinity

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""

import pickle
import operator
import binascii, base58


def dic2btye(file_handler, **kwargs):
    """

    :param kwargs:
    :return:
    """
    return pickle.dump(kwargs, file_handler)


def crypto_channel(file_handler, **kwargs):
    """
    :param kwargs:
    :return:
    """
    return dic2btye(file_handler, **kwargs)

def uncryto_channel(file_handler):
    """

    :param file_handler:
    :return:
    """
    return byte2dic(file_handler)

def byte2dic(file_hander):
    """

    :param file_hander:
    :return:
    """
    return pickle_load(file_hander)

def pickle_load(file):
    """

    :param file:
    :return:
    """
    pickles = []
    while True:
        try:
            pickles.append(pickle.load(file))
        except EOFError:
            return pickles


class tncSimpleCrypto(object):
    '''
        A new class to provide a simple crypto algorithm.
        It will return a crypto data with 128 / 256 /512 bytes.
    '''
    EOF = 'e0fe0f'
    SOF = 'b0fb0f'

    parity_bytes   = 4
    length_bytes   = 4
    rshift_bit     = 5

    def __init__(self, prime=13):
        # don't change the base_prime before we could write this number to the DB
        self.prime          = prime

    @classmethod
    def encrypt40(cls, value: str, base = '1234567890ABCDEF'):
        '''
        :Description:
        :param value:
        :param base: means the base private key information
        :return:
        '''
        try:
            crypt_result    = cls.ascii_str(value)
            private_result  = cls.ascii_str(value)
            extra_length    = (cls.parity_bytes + cls.length_bytes) * 2
            expected_length = 58 - extra_length
            crypt_value     = crypt_result[0] + private_result[0]
            crypt_value     = cls.system_remove_same_bytes(crypt_value, expected_length)

            if not crypt_value:
                return None

            crypt_length= len(crypt_value)
            if 58 < crypt_length:
                return None
            else:
                # padding to 58 bytes
                crypt_value += '0'*(58 - crypt_length - extra_length) + crypt_value[1] + private_result[1]

            if 58 != len(crypt_value):
                # print('Length Error. {}-{}'.format(crypt_value, len(crypt_value)))
                return None
            crypt_value = base58.b58encode(binascii.a2b_hex(crypt_value))

            return crypt_value
        except Exception as e:
            # print('Type error: {}'.format(e))
            return None

    @classmethod
    def decrypt40(cls, value: str):
        decrypt_value   = binascii.b2a_base64(base58.b58decode(value)).decode()
        split_length    = int(decrypt_value[-1:-5:-1], 16)
        decrypt_value   = decrypt_value[0:split_length]
        crypt_value     = ''.join(decrypt_value[0::2]).strip()
        base_value      = ''.join(decrypt_value[1::2]).strip()[-1::-1]

        if not (crypt_value.startswith(cls.SOF) and crypt_value.endswith(cls.EOF) and \
                base_value.startswith(cls.SOF) and crypt_value.endswith(cls.EOF)):
            # print ('decrypt failed')
            return None

        origin_value    = cls.system_recover_bytes(crypt_value)
        base_value      = cls.system_recover_bytes(base_value)

        return (origin_value, base_value)

    @classmethod
    def encrypt256(cls, value: str, base = '1234567890ABCDEF'):
        '''
        :Description:
        :param value:
        :param base: means the base private key information
        :param specified_extent: user specified the result length, be supported in the future???
        :return:
        '''
        try:
            crypt_value = cls.system_extend_bytes(value)
            private_key = cls.system_extend_bytes(base)
            length_sum  = len(crypt_value + private_key)

            if 244 >= length_sum:
                crypt_value     = ''.join(list(map(lambda x, y: x+y, crypt_value, private_key[-1::-1]))) + '0' * (244 - length_sum) + '{:04x}'.format(length_sum)
                encrypted_data  = base58.b58encode(binascii.a2b_base64(crypt_value))
            else:
                return None
        except Exception as e:
            # print('Type error: {}'.format(e))
            return None

        return encrypted_data

    @classmethod
    def decrypt256(cls, value: str):
        decrypt_value   = binascii.b2a_base64(base58.b58decode(value)).decode()
        split_length    = int(decrypt_value[-1:-5:-1], 16)
        decrypt_value   = decrypt_value[0:split_length]
        crypt_value     = ''.join(decrypt_value[0::2]).strip()
        base_value      = ''.join(decrypt_value[1::2]).strip()[-1::-1]

        if not (crypt_value.startswith(cls.SOF) and crypt_value.endswith(cls.EOF) and \
                base_value.startswith(cls.SOF) and crypt_value.endswith(cls.EOF)):
            # print ('decrypt failed')
            return None

        origin_value    = cls.system_recover_bytes(crypt_value)
        base_value      = cls.system_recover_bytes(base_value)

        return (origin_value, base_value)

    @property
    def BASIC_CRYPT_OPTION(self):
        return [16, 32, 48, 64, 96, 128]

    @classmethod
    def system_extend_bytes(cls, value: str):
        '''
        :Descriptions:
        :param value: be used to encrypt.
        :return:
        '''
        try:
            result      = ''.join(list(cls.ascii_str(value)))
            extent_str  = cls.SOF + result + cls.EOF
            # add log here.
        except Exception as e:
            # print ('Invalid value is used to be encrypted! {}'.format(e))
            return None

        return extent_str

    @classmethod
    def system_recover_bytes(cls, value: str):
        try:
            temp_value      = value.strip(cls.SOF).strip(cls.EOF)
            temp_length     = len(temp_value) - cls.parity_bytes - cls.length_bytes
            origin_value    = temp_value[0:temp_length]
            parity          = int(temp_value[temp_length:temp_length+4], 16)
            origin_length   = int(temp_value[temp_length+4:temp_length+8], 16)

            crypt_value = list(map(lambda x, y: int(x+y, 16), origin_value[::2], origin_value[1::2]))
            crypt_value = ''.join(list(map(chr, crypt_value)))
            # add log here.
        except Exception as e:
            # print ('decrypt failed! {}'.format(e))
            return None

        return crypt_value

    @classmethod
    def system_remove_same_bytes(cls, value: str, expect_length=0):
        '''
        :Descriptions:
        :param value: be used to encrypt.
        :return:
        '''
        try:
            temp_length = len(value)
            if 0 != operator.imod(temp_length, 1):
                # padding
                value += '0'

            # to calculate some basic parameters
            if temp_length in cls.BASIC_CRYPT_OPTION:
                split_base = temp_length
            else:
                base_idx = operator.irshift(temp_length, 4)
                base_idx = base_idx - 1 if base_idx else 0
                split_base  = cls.BASIC_CRYPT_OPTION[base_idx]
            split_count = temp_length / split_base

            # to organize the data wich will be used to crypt
            reverse_base = list(value[1::2])
            reverse_base.reverse()
            temp_value  = list(map(lambda x, y: x+y, value[::2], reverse_base))
            temp_value  = [temp_value[split_base*split_idx:split_base*(split_idx+1):] for split_idx in range(split_count)]
            left_length = operator.imod(temp_length, split_base)
            left_bytes  = value[temp_length-left_length::]

            # start to decrease the
            temp_result = cls.padding_by_rid_data(temp_value)
            stop_flag   = temp_result[2]
            res_value   = temp_result[0] + left_bytes + temp_result[1]
            if stop_flag:
                return res_value
            else:
                if expect_length > len(res_value):
                    return res_value
                else:
                    res_value = cls.system_remove_same_bytes(left_bytes, expect_length - temp_result[1])

            return res_value+left_bytes + temp_result[1], True
            # add log here.
        except Exception as e:
            # print ('Invalid value is used to be encrypted! {}'.format(e))
            return value, True

    @classmethod
    def system_recover_same_bytes(cls, value: str):
        try:
            temp_value      = value.strip(cls.SOF).strip(cls.EOF)
            temp_length     = len(temp_value) - cls.parity_bytes - cls.length_bytes
            origin_value    = temp_value[0:temp_length]
            parity          = int(temp_value[temp_length:temp_length+4], 16)
            origin_length   = int(temp_value[temp_length+4:temp_length+8], 16)

            crypt_value = list(map(lambda x, y: int(x+y, 16), origin_value[::2], origin_value[1::2]))
            crypt_value = ''.join(list(map(chr, crypt_value)))
            # add log here.
        except Exception as e:
            # print ('decrypt failed! {}'.format(e))
            return None

        return crypt_value

    @classmethod
    def ascii_str(cls, value):
        ascii_bytes = ''.join(['{:02X}'.format(asc_value) for asc_value in list(map(ord, value))])
        extra_bytes = ''.join('{:04X}'.format(cls._parity(value))) + ''.join('{:04X}'.format(len(value)))

        return ascii_bytes, extra_bytes

    @classmethod
    def padding_by_rid_data(cls, value):
        '''
        :Descriptions
        :param value:
        :return:
        '''
        try:
            # operator.irshift(split_base, 2) - record the column index. variable length
            # left 2 bytes: xxxxyyyyvvvvzzzz -- fixed length
            #               xxxx -- the number value
            #               yyyy -- indicate that which base is used.
            #               vvvv -- indicate the min index( exchange to shift operation value)
            #               zzzz -- record the row index
            pad_base    = len(value)
            pad_map     = {}
            for item in set(value):
                key = value.count(item)
                if key not in pad_map.keys():
                    pad_map[key] = []
                pad_map[key].append(item)

            # to find the max value
            count_list = pad_map.keys()
            count_list.sort(reverse=True)



        except Exception as e:
            # print ('{}'.format(e))
            return value, '', True

    # @classmethod
    # def ascii_str_after_remove(cls, value):
    #     ascii_string    = cls.ascii_str(value)
    #     ascii_length    = len(ascii_string)
    #     split_point     = ascii_length - cls.parity_bytes - cls.length_bytes
    #     temp_string     = ascii_string[::split_point]
    #
    #     suffix_string   = ascii_string[ascii_length-split_point::]
    #
    #     loop = split_point / 32
    #     for i in range(loop):
    #         temp_set = list(set())

    # @classmethod
    # def gen_private_key(cls, base):
    #     keys        = datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
    #     keys_length = len(keys)
    #     if 0 != operator.imod(keys_length, 2):
    #         keys += '0'
    #
    #     keys_hex = list(map(lambda x, y: int(x+y, 16), keys[0::2], keys[1::2]))
    #
    #     return keys_hex


    def user_extend_bytes(self, value: str, spec_extent = 0):
        pass

    @classmethod
    def _parity(cls, value: str):
        temp_ascii  = list(map(ord, value))
        value_length= len(value)
        value_comp  = value_length % 2  # value completion
        if 0 != value_comp:
            temp_ascii.extend([0] * value_comp)

        asc_group = list(map(lambda x, y: operator.ior(operator.lshift(x, 8), y), temp_ascii[0::2], temp_ascii[1::2]))

        _parity_value = 0
        for v in asc_group:
            _parity_value = operator.ixor(_parity_value, v)

        if 0xFF >= value_length:
            _parity_value = operator.ixor(_parity_value, value_length << 8)
        else:
            _parity_value = operator.ixor(_parity_value, value_length)

        return _parity_value
