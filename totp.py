#!/usr/bin/python3

import hashlib
import hmac
import struct
import os
import time


def otp(key, counter, hash="SHA1", otp_len=6):
    """This function is used to generate an OTP based on the counter using HMAC,
    The algorithm is defined in RFC4226. The algorithm in general is:
    Steps:
    1. calculate h_bytes = hmac.digest(key, counter, hash_algo)
    2. get offset = last 4 bits of the byte array
    3. get 4 bytes from the 'offset' postion in the byte array
    4. return required number of bytes

    Arguments:
        key: the key used to perform HMAC, the length depends on the hash being
            used, eg: for SHA-1, key should be atleast 20bytes, for SHA-256 it
            should be atleast 32bytes

        counter: the counter value to be used as the data in the hmac

        hash: the hash algorithm to be used to compute hmac, by default it's
            SHA-1

        otp_len: the length of OTP to be returned, the default value is 6

    Returns:
        str: OTP string of length otp_len"""

    counter = struct.pack(">Q", counter)

    h_bytes = hmac.digest(key , counter, hashlib.sha1)
    offset = h_bytes[-1] & 0xf

    truncated_hash = (h_bytes[offset] & 0x7f) << 24 | \
        (h_bytes[offset + 1] & 0xff) << 16 | \
        (h_bytes[offset + 2] & 0xff) << 8  | \
        (h_bytes[offset + 3] & 0xff)

    return str.rjust(str(truncated_hash % pow(10, otp_len)), otp_len, '0')

def get_totp_counter(date_str, time_step=30):
    """This function returns the counter value from the epoch time, evaluated
    based on the time_step. the counter is evaluated as the epoch_time / time_step

    Arguments:
        date_str: date string at which the OTP has to be calculated. the format
            that is being used is "%A, %d %B %Y %H:%M:%S"
            eg: `Friday, 21 December 2018 16:29:28`

        time_step: the step value for time on which the OTP counter is calculated
            The default value is 30s

    Returns:
        int: counter value for current UTC time given time_step"""

    os.environ["TZ"] = "UTC"
    time.tzset()
    t = time.strptime(date_str, "%A, %d %B %Y %H:%M:%S")
    return int(time.mktime(t) / time_step)

if __name__ == '__main__':
    #Friday, 21 December 2018 16:29:28 - 084342
    #Saturday, 22 December 2018 13:11:53 - 411907
    #Tuesday, 25 December 2018 12:15:03 - 617041
    key = b""
    counter = get_totp_counter("Friday, 21 December 2018 16:29:28")
    print ("Friday, 21 December 2018 16:29:28", otp(key, counter))

    counter = get_totp_counter("Saturday, 22 December 2018 13:11:53")
    print ("Saturday, 22 December 2018 13:11:53", otp(key, counter))

    counter = get_totp_counter("Tuesday, 25 December 2018 12:15:03")
    print ("Tuesday, 25 December 2018 12:15:03", otp(key, counter))

    counter = get_totp_counter("Tuesday, 1 January 2019 00:00:00")
    print ("Tuesday, 1 January 2019 00:00:00", otp(key, counter))
