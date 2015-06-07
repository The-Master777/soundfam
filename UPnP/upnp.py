#!/usr/bin/env python
# -*- coding: utf-8 -*-

import ssdp

class UPnPDevice(object):
    # Value of the SSDP discovery ST parameter
    _DISCOVER_ST = ssdp.SSDPServiceDiscoverer.ST_VALUES['rootdevice']

    def __init__(self, ssdpResponse):
        super(UPnPDevice, self).__init__()
        
        self.ssdpResponse = ssdpResponse

    def __repr__(self):
        return '<UPnPDevice from %s>' % self.ssdpResponse.__repr__()

    @staticmethod
    def _yieldDevices(c, rs, **kwargs):
        if rs is None:
            return

        for r in rs:
            # Create new instance
            yield c(r, **kwargs)

    @classmethod
    def discover(c, st=None, **kwargs):
        """Search for UPnP devices and yield encapsulated device responses."""

        st = st or c._DISCOVER_ST
        rs = ssdp.BasicSSDPServiceDiscoverer().discover(st)

        #yield from UPnPDevice._yieldDevices(c, rs, **kwargs)
        for bar in UPnPDevice._yieldDevices(c, rs, **kwargs):
            yield bar

    @classmethod
    def fromUuid(c, deviceId, **kwargs):
        rs = ssdp.BasicSSDPServiceDiscoverer().discoverDevice(deviceId)

        #yield from UPnPDevice._yieldDevices(c, rs, **kwargs)
        for bar in UPnPDevice._yieldDevices(c, rs, **kwargs):
            return bar # Return FIRST result, as the uuid is assumed to be unique

        return None


class UPnPMediaRenderer(UPnPDevice):
    # Service Type of UPnP MediaRenderers
    _ST_DEVICE_MEDIA_RENDERER = 'urn:schemas-upnp-org:device:MediaRenderer:1'

    # Value of the SSDP discovery ST parameter
    _DISCOVER_ST = _ST_DEVICE_MEDIA_RENDERER

    def __init__(self, ssdpResponse):
        super(UPnPMediaRenderer, self).__init__(ssdpResponse)

#class SonosZonePlayer(UPnPMediaRenderer):
#    _DISCOVER_ST = 'urn:schemas-upnp-org:device:ZonePlayer:1'

if __name__ == '__main__':
    for s in UPnPMediaRenderer.discover():
        print(s)