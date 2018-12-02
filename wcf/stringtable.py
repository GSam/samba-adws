from io import BytesIO

from .dictionary import dictionary, inverted_dict
from .datatypes import MultiByteInt31, Utf8String


class StringTable(object):

    def __init__(self):
        self.num2str = dictionary.copy()
        self.str2num = inverted_dict.copy()
        # MC-NBFSE protocol use even ones
        # we use odd ones to extend
        # 1, 3, 5, ...
        self.index = 1

    def add_string(self, string):
        if string not in self.str2num:
            self.num2str[self.index] = string
            self.str2num[string] = self.index
            self.index += 2

    def get_string(self, index):
        return self.num2str[index]

    def get_index(self, string):
        return self.str2num[string]

    def feed(self, fp):
        # will move fp forward
        size = MultiByteInt31.parse(fp).value
        table_data = fp.read(size)
        table = BytesIO(table_data)

        while table.tell() < size:
            string = Utf8String.parse(table)
            self.add_string(string)
