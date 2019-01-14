# TOTP

Time based OTP is a method that generates random numbers of a fixed size. It uses the [HOTP](https://en.wikipedia.org/wiki/HMAC-based_One-time_Password_algorithm) method to generate a keyed HMAC. The [RFC4226](https://tools.ietf.org/html/rfc4226) defines the hash algorithm to be SHA1. HMAC-SHA1 requires a 20 byte key and produces a 20 byte output. The final output is then truncated to produce a required size OTP.

The RFC states, that largest OTP produced by HOTP is 4 bytes, which can then be reduced by taking a modulo a power of 10 to reduce the number of digits.

HOTP can be described as follows:
1. Calculate `h_bytearray = HMAC-SHA1(k, c)` where `k` is the 20 byte secret key and `c` is the data
2. Calculate the `offset` value which is equal to the last 4 Least significant bits of the HMAC produced. So `offset = h_bytearray[-1] & 0xf`
3. Now, concatenate 4 bytes from the `offset`, that is the value of the raw OTP produced.
  ```
   otp = (h_bytearray[offset]     & 0x7f) << 24 |
         (h_bytearray[offset + 1] & 0xff) << 16 |
         (h_bytearray[offset + 2] & 0xff) << 8  |
         (h_bytearray[offset + 3] & 0xff)
  ```
  _Note_ : the first byte is masked to `0x7f` to keep the final value less than 32 bits.

4. The final value of the `otp` is `otp (mod 10^d)` where `d` is the number of digits of OTP.

The value `c` in the first step is a 32-bit counter that needs to be synchronized between the server and the OTP device to be able to verify it.

For TOTP, the counter value is replaced with the Epoch Time broken into `time_step`. Time step can be defined as the time interval for which the OTP remains invariant to make it verifiable. The default value of `time_step` is 30s. For example: if we consider t=230s from Epoch, the `counter = floor(230 / 30) = 7`. So the TOTP is calculated as `HOTP(key, 7)`.

The HOTP RFC limits the HMAC to use SHA1 only, but [TOPT](https://en.wikipedia.org/wiki/Time-based_One-time_Password_algorithm), as published in [RFC6238](https://tools.ietf.org/html/rfc6238), states that SHA256 and SHA512 too can be used for calculating HMAC.

The problem states the TOTP complies to RFC4226 and uses SHA1.

```
$ python3 totp.py
Friday, 21 December 2018 16:29:28 084342
Saturday, 22 December 2018 13:11:53 411907
Tuesday, 25 December 2018 12:15:03 617041
Tuesday, 1 January 2019 00:00:00 301554
```

So the answer is `301554`

Code: [totp.py](./totp.py)
