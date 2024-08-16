#!/usr/bin/env python2
# encoding: utf-8
# Copyright 2016 Timo Schmid
from __future__ import print_function, unicode_literals, absolute_import

import warnings
from io import BytesIO, StringIO
from collections import defaultdict

from wcf.records import Record, print_records
from wcf.datatypes import MultiByteInt31, Utf8String
from wcf.dictionary import dictionary

old_dictionary = dictionary.copy()
dictionary_cache = defaultdict(dict)

idx = 1

def build_dictionary(fp, key):
    global idx

    size = MultiByteInt31.parse(fp).value
    print("Dictionary table: {} bytes".format(size))
    table_data = fp.read(size)
    table = BytesIO(table_data)

    while table.tell() < size:
        string = Utf8String.parse(table)
        assert idx not in dictionary_cache[key]
        dictionary_cache[key][idx] = string.value
        idx += 2
    dictionary.clear()
    dictionary.update(old_dictionary)
    dictionary.update(dictionary_cache[key])

    for i, value in dictionary_cache[key].items():
        print('{}: {}'.format(i, value))
    return dictionary_cache[key]
