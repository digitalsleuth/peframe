#!/usr/bin/env python3
# -*- coding: utf-8 -*-


def get_wanted_chars():
    wanted_chars = ["\0"] * 256

    for i in range(32, 127):
        wanted_chars[i] = chr(i)

    wanted_chars[ord("\t")] = "\t"
    return "".join(wanted_chars)


def get_wanted_chars_unicode():
    wanted_chars = ["\0"] * 256

    for i in range(32, 127):
        wanted_chars[i] = chr(i)

    wanted_chars[ord("\t")] = "\t"
    return "".join(wanted_chars)


def get_wanted_bytes():
    table = bytearray(256)
    for i in range(256):
        table[i] = ord("\0")

    for i in range(32, 127):
        table[i] = i

    table[ord("\t")] = ord("\t")
    return bytes(table)


def get_result(filename):
    THRESHOLD = 4
    with open(filename, "rb") as f:
        raw = f.read()
        translated = raw.translate(get_wanted_bytes())
        decoded = translated.decode("latin1", errors="ignore")
        return [s for s in decoded.split("\0") if len(s) >= THRESHOLD]
