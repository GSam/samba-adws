#!/usr/bin/env python2
# encoding: utf-8
# Copyright 2016 Timo Schmid
from __future__ import print_function, unicode_literals, absolute_import

import logging
import gssapi
from .negotiate import NegotiateStream

from samba.param import LoadParm
from samba.credentials import Credentials
from samba import gensec, auth

log = logging.getLogger(__name__ + '.GENSECStream')


class GENSECStream:
    def __init__(self, stream, server_name, creds):
        self._inner = NegotiateStream(stream)
        self.client_ctx = None
        self._readcache = b''

        self.settings = {}

        self.settings["lp_ctx"] = self.lp_ctx = LoadParm()
        self.lp_ctx.load_default()

        self.settings["target_hostname"] = server_name

        self.server_name = server_name
        self.creds = creds

    def negotiate(self):
        self.client_ctx = gensec.Security.start_client(settings=self.settings)

        self.client_ctx.set_credentials(self.creds)

        self.client_ctx.start_mech_by_name("spnego")
        self.client_ctx.want_feature(gensec.FEATURE_SEAL)
        self.client_ctx.want_feature(gensec.FEATURE_SIGN)
        self.client_ctx.set_target_service("HOST")
        self.client_ctx.set_target_hostname(self.server_name)

        token = b''
        client_finished = False
        while not client_finished:
            log.debug('Doing step')
            client_finished, client_to_server = self.client_ctx.update(token)

            self._inner.write(client_to_server)

            if not client_finished:
                token = self._inner.read()
            else:
                log.debug('GSSAPI Handshake done')
                break

    def write(self, data):
        if not self.client_ctx:
            self.negotiate()

        while data:
            data2 = data[:0xFC00]
            e_data = self.client_ctx.wrap(data2)
            self._inner.write(e_data)
            data = data[0xFC00:]

    def read(self, count=None):
        if not self.client_ctx:
            self.negotiate()

        if count is None:
            sub = self._inner.read()
            return self.client_ctx.unwrap(sub)

        data_final = b''
        while count > 0:
            data = self._readcache[:count]
            self._readcache = self._readcache[count:]
            ld = len(data)
            log.debug('Got %d bytes from cache', ld)
            count -= ld
            data_final += data
            if count:
                log.debug('Still %d bytes missing', count)
                sub = self._inner.read()
                self._readcache += self.client_ctx.unwrap(sub)
        return data_final

    def close(self):
        self._inner.close()
