#!/usr/bin/env python2
# encoding: utf-8
# Copyright 2016 Timo Schmid
from __future__ import print_function, unicode_literals, absolute_import

import logging
import gssapi
from .negotiate import NegotiateStream

log = logging.getLogger(__name__ + '.GSSAPIStream')


class GSSAPIStream:
    def __init__(self, stream, server_name,
                 flags=(gssapi.RequirementFlag.mutual_authentication |
                        gssapi.RequirementFlag.confidentiality |
                        gssapi.RequirementFlag.integrity)):
        self._inner = NegotiateStream(stream)
        if isinstance(server_name, str):
            server_name = gssapi.Name(server_name, name_type=gssapi.NameType.hostbased_service)
        self.server_name = server_name
        self.flags = flags
        self.client_ctx = None
        self._readcache = b''

    def negotiate(self):
        self.client_ctx = gssapi.SecurityContext(name=self.server_name, usage='initiate',
                                                 flags=self.flags)

        token = b''
        while not self.client_ctx.complete:
            log.debug('Doing step')
            token = self.client_ctx.step(token)

            self._inner.write(token)
            if not self.client_ctx.complete:
                token = self._inner.read()
            else:
                log.debug('GSSAPI Handshake done')

    def write(self, data):
        if not self.client_ctx:
            self.negotiate()

        data = self.client_ctx.encrypt(data)
        self._inner.write(data)

    def read(self, count=None):
        if not self.client_ctx:
            self.negotiate()

        if count is None:
            sub = self._inner.read()
            return self.client_ctx.decrypt(sub)

        while count > 0:
            data = self._readcache[:count]
            self._readcache = self._readcache[count:]
            ld = len(data)
            log.debug('Got %d bytes from cache', ld)
            count -= ld
            if count:
                log.debug('Still %d bytes missing', count)
                sub = self._inner.read()
                self._readcache += self.client_ctx.decrypt(sub)
        return data

    def close(self):
        self._inner.close()

from samba.param import LoadParm
from samba.credentials import Credentials
from samba import gensec, auth

class GENSECStream:
    def __init__(self, stream): #, server_name,
                 # flags=(gssapi.RequirementFlag.mutual_authentication |
                 #        gssapi.RequirementFlag.confidentiality |
                 #        gssapi.RequirementFlag.integrity)):
        self._inner = NegotiateStream(stream)
        # if isinstance(server_name, str):
        #     server_name = gssapi.Name(server_name, name_type=gssapi.NameType.hostbased_service)
        # self.server_name = server_name
        # self.flags = flags
        self.client_ctx = None
        self._readcache = b''

        self.settings = {}

        self.settings["lp_ctx"] = self.lp_ctx = LoadParm()
        self.lp_ctx.load_default()

        self.settings["target_hostname"] = self.lp_ctx.get("netbios name")

    def negotiate_server(self):
        token = self._inner.read()

        self.client_ctx = gensec.Security.start_server(settings=self.settings,
                auth_context=auth.AuthContext(lp_ctx=self.lp_ctx))
        # gssapi.SecurityContext(name=self.server_name, usage='initiate',
                          #                       flags=self.flags)


        creds = Credentials()
        creds.guess(self.lp_ctx)
        creds.set_machine_account(self.lp_ctx)
        self.client_ctx.set_credentials(creds)

        self.client_ctx.start_mech_by_name("spnego")

        # token = b''

        server_finished = False
        while not server_finished:
            log.debug('Doing step')
            server_finished, server_to_client = self.client_ctx.update(token)

            self._inner.write(server_to_client)

            if not server_finished:
                token = self._inner.read()
            else:
                log.debug('GSSAPI Handshake done')
                self._inner.write_handshake_done(server_to_client)

        # while not self.client_ctx.complete:
        #     log.debug('Doing step')
        #     token = self.client_ctx.step(token)
        #
        #     self._inner.write(token)
        #     if not self.client_ctx.complete:
        #         token = self._inner.read()
        #     else:
        #         log.debug('GSSAPI Handshake done')

    def write(self, data):
        if not self.client_ctx:
            self.negotiate()

        data = self.client_ctx.wrap(data)
        self._inner.write(data)

    def read(self, count=None):
        if not self.client_ctx:
            self.negotiate()

        if count is None:
            sub = self._inner.read()
            return self.client_ctx.unwrap(sub)

        while count > 0:
            data = self._readcache[:count]
            self._readcache = self._readcache[count:]
            ld = len(data)
            log.debug('Got %d bytes from cache', ld)
            count -= ld
            if count:
                log.debug('Still %d bytes missing', count)
                sub = self._inner.read()
                self._readcache += self.client_ctx.unwrap(sub)
        return data

    def close(self):
        self._inner.close()
