#!/usr/bin/env python
# -*- coding: utf-8 -*-

import ssdp

class UPnPMediaRenderer(object):
    _ST_DEVICE_MEDIA_RENDERER = 'urn:schemas-upnp-org:device:MediaRenderer:1'

    def __init__(self, arg):
        super(UPnPMediaRenderer, self).__init__()
        self.arg = arg

    @staticmethod
    def discover():
        rs = ssdp.BasicSSDPServiceDiscoverer().discover(UPnPMediaRenderer._ST_DEVICE_MEDIA_RENDERER)

        if rs is not None:
            for r in rs: print(r)


if __name__ == '__main__':
    UPnPMediaRenderer.discover()