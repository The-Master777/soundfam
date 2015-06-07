#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket as s
import time
import re
from uuid import uuid4
from abc import ABCMeta, abstractmethod
from requests.structures import CaseInsensitiveDict

class SSDPServiceDiscoverer(object):
    """An implementation of the discovery process as described by SSDP, the 
    Simple Service Discovery Protocol. This can be used to discover present 
    UPnP-Devices and -Services in the local network."""

    __metaclass__ = ABCMeta

    _MCAST_ADDR = '239.255.255.250'
    _MCAST_PORT = 1900

    _SSDP_ST_SSDP_ALL = 'ssdp:all'
    _SSDP_ST_UPNP_ROOTDEVICE = 'upnp:rootdevice'
    _SSDP_ST_UUID_TEMPLATE = 'uuid:{device_uuid}'

    # A dictionary for known non-parameterized M-SEARCH request ST-Values
    ST_VALUES = {'all': _SSDP_ST_SSDP_ALL, 'rootdevice': _SSDP_ST_UPNP_ROOTDEVICE}

    # Some default values
    _SSDP_INFO = {'ssdp_address': _MCAST_ADDR, 'ssdp_port': _MCAST_PORT}
    _SSDP_DISCOVERY_DEFAULT_ST = _SSDP_ST_SSDP_ALL # Find services of all SSDP-enabled devices
    _SSDP_DISCOVERY_DEFAULT_TIMEOUT = 2 # 1 second timeout
    _SSDP_DISCOVERY_DEFAULT_RETRY_DELAY = 0.01 # Approx. 10ms
    _SSDP_DISCOVERY_DEFAULT_TRIES_COUNT = 2 # Number of attempts

    #: The MX Header field of the SSDP discovery M-Search request as described in <http://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf> defines the wait time in seconds. It MUST be greater than or equal to 1 and SHOULD be less than 5 inclusive. Device responses SHOULD be delayed a random duration between 0 and this many seconds to balance load for the control point when it processes responses. Integer.
    _SSDP_DISCOVERY_DEFAULT_MX = 1 # MX = 1
    _SSDP_DISCOVERY_DEFAULT_TTL = 10 # TTL = 10
    _SSDP_DISCOVERY_RECV_BUFFER_SIZE = 1 << 13 # Buffer size is 8192 bytes. Longer recv. messages might be broken.

    # The CRLF terminal string
    _CRLF = "\r\n"

    # The basic structure of a M-SEARCH request
    _MSEARCH_REQUEST_TEMPLATE = _CRLF.join([
        'M-SEARCH * HTTP/1.1',
        'HOST: {ssdp_address}:{ssdp_port}',
        'MAN: "ssdp:discover"',
        'MX: {mx}',
        'ST: {st}',
        '', # Terminate with two CRLF
        '',
    ])

    def discover(self, serviceType=_SSDP_DISCOVERY_DEFAULT_ST, timeout=_SSDP_DISCOVERY_DEFAULT_TIMEOUT, numTries=_SSDP_DISCOVERY_DEFAULT_TRIES_COUNT, retryDelaySeconds=_SSDP_DISCOVERY_DEFAULT_RETRY_DELAY, mx=_SSDP_DISCOVERY_DEFAULT_MX, ttl=_SSDP_DISCOVERY_DEFAULT_TTL, uuid=None):
        """Perform a discovery for default or specified device or service in the local network.

        :param str serviceType: The ST service type descriptor of the service to discover.
        :param int timeout: The time to wait for discovery replies.
        :param int numTries: The number of times to emit a M-SEARCH request.
        :param float retryDelaySeconds: The time in seconds to wait before emitting the next M-SEARCH request.
        :param mx: The M-SEARCH request MX parameter.
        :param int ttl: The TTL of the broadcast message.
        :param uuid: The unique identifier of the search to use, or None if a random id should be generated.
        """

        # Use provided UUID or generate a new one if needed
        uuid = uuid or uuid4()

        # TODO: Handle non-ASCII M-SEARCH request MX and ST header field values.
        # HTTP header field values cannot contain characters outside of the 
        # ISO-8859-1 character set. Only ASCII-characters are guaranteed to work.
        #
        #  Options:
        #   - Reject invalid values
        #   - Apply Percent Encoding (urlencoding)
        #   - Apply MIME Encoding ("=?UTF-8?Q?...?=")
        #

        # Create request message
        m = self._MSEARCH_REQUEST_TEMPLATE.format(mx=mx, st=serviceType, **self._SSDP_INFO)

        # Initialize Socket
        s.setdefaulttimeout(timeout)
        sock = s.socket(s.AF_INET, s.SOCK_DGRAM, s.IPPROTO_UDP)
        sock.setsockopt(s.IPPROTO_IP, s.IP_MULTICAST_TTL, ttl)
        try:
            # Emit M-SEARCH request numTries times
            for i in range(numTries):
                sock.sendto(m, (self._SSDP_INFO['ssdp_address'], self._SSDP_INFO['ssdp_port']))

                # block a small amount of time until next try
                if i < numTries - 1:
                    time.sleep(retryDelaySeconds) 

            # Try to receive the responses
            while True:
                try:
                    # FIXME: This will probably destroy the message if the  
                    # response is longer than _SSDP_DISCOVERY_RECV_BUFFER_SIZE!
                    r = sock.recv(self._SSDP_DISCOVERY_RECV_BUFFER_SIZE)

                    if(r is None or len(r) <= 0):
                        continue # Failed to read

                    # Pass response to handler:
                    #   r is given as argument together with unique id the 
                    #   handler can either process the response immediately 
                    #   or can wait until it is again called with None as 
                    #   response-argument to reduce the delay the processing 
                    #   incorporates.
                    self._handleResponse(r, uuid)  # *---------,
                except s.timeout:                  #           |
                    break                          #           | F
                                                   #           | i
        finally:                                   #           | N
            try:                                   #           | A
                sock.close()                       #           | L
                                                   #           | i
            finally:                               #           | Z
                # Finalize the handling of SSDP responses      | E
                # Return whatever is returned by the handler   |
                return self._handleResponse(None, uuid) # <----´

    def discoverRootdevices(self, timeout=_SSDP_DISCOVERY_DEFAULT_TIMEOUT, numTries=_SSDP_DISCOVERY_DEFAULT_TRIES_COUNT, retryDelaySeconds=_SSDP_DISCOVERY_DEFAULT_RETRY_DELAY, mx=_SSDP_DISCOVERY_DEFAULT_MX, ttl=_SSDP_DISCOVERY_DEFAULT_TTL, uuid=None):
        return self.discover(serviceType=self._SSDP_ST_UPNP_ROOTDEVICE, timeout=timeout, numTries=numTries, retryDelaySeconds=retryDelaySeconds, mx=mx, ttl=ttl, uuid=uuid)

    def discoverDevice(self, deviceId, timeout=_SSDP_DISCOVERY_DEFAULT_TIMEOUT, numTries=_SSDP_DISCOVERY_DEFAULT_TRIES_COUNT, retryDelaySeconds=_SSDP_DISCOVERY_DEFAULT_RETRY_DELAY, mx=_SSDP_DISCOVERY_DEFAULT_MX, ttl=_SSDP_DISCOVERY_DEFAULT_TTL, uuid=None):
        if deviceId is None:
            raise ValueError('The deviceId must not be None')

        st = deviceId

        if not st.startswith('uuid:'):
            # format device uuid ST parameter
            st = self._SSDP_ST_UUID_TEMPLATE.format(device_uuid=deviceId)

        return self.discover(serviceType=st, timeout=timeout, numTries=numTries, retryDelaySeconds=retryDelaySeconds, mx=mx, ttl=ttl, uuid=uuid)

    @abstractmethod
    def _handleResponse(self, response, uuid):
        """Abstract. The method that is responsible for handling M-SEARCH response 
        messages. This method is called for every response received for a discovery
        operation. It is also called when a discovery is finished. In this case the
        response-parameter will be None. This allows you to cache all received 
        response messages until the discovery is finished to reduce the delay of
        processing a newly encountered response.

        :param str response: The response that was received or None if discovery is finished.
        :param uuid: The identifier of the discovery process where the response belongs to.
        """

        pass

class BasicSSDPServiceDiscoverer(SSDPServiceDiscoverer):
    """The BasicSSDPServiceDiscoverer is designed to efficiently perform a discovery 
    of UPnP-Services. The received response messages are cached during the discovery
    and parsed afterwards. Each response with a unique URN is stored as SSDPResponse.
    """

    def __init__(self):
        """Initializes the BasicSSDPServiceDiscoverer instance"""
        super(BasicSSDPServiceDiscoverer, self).__init__()

        self._responseCache = {}

    def _handleResponse(self, response, uuid):
        """Parses all responses received for a discovery and returns a list of SSDPResponse.
        The responses are cached until the finalization-phase of the discovery-process is 
        entered. Then the cached entries are parsed.

        :param str response: The response to handle.
        :param uuid: The unique identifier associated with a discovery process.
        """

        # Check if we need to cache a new response
        # Else: Finalize (Process entries)
        if response is not None:
            if uuid not in self._responseCache:
                self._responseCache[uuid] = []

            self._responseCache[uuid].append(response)

            return None

        # Check if there are any entries
        if uuid not in self._responseCache:
            return None

        # Get cached entries and delete cache entry
        entries = self._responseCache[uuid]
        del self._responseCache[uuid]

        resps = set()

        # Parse all responses
        for r in entries:
            resps.add(BasicSSDPServiceDiscoverer.SSDPResponse(r))

        return resps

    class SSDPResponse(object):
        """A container class for received SSDP responses."""

        def __init__(self, response):
            """Initializes the SSDPResponse instance based on a response string"""
            super(BasicSSDPServiceDiscoverer.SSDPResponse, self).__init__()

            # Initialize fields
            self.Location = None
            self.USN = None
            self.ST = None
            self.Headers  = CaseInsensitiveDict()

            # Parse response
            self._fromString(response)

        def _fromString(self, str):
            """Parses a response string and assigns values to the SSDPResponse object.

            :param str str: The string to parse."""

            # Lazy method to parse all http-headers
            h = CaseInsensitiveDict({k.lower(): v for k, v in dict(re.findall(r'(?P<name>.*?): (?P<value>.*?)\r\n', str)).items()})
            self.Headers = h

            # Set major fields
            if 'location' in h:
                self.Location = h['location']

            if 'USN' in h:
                self.USN = h['USN']

            if 'ST' in h:
                self.ST = h['ST']

        def __repr__(self):
            return '<SSDPResponse from %s at %s; Headers: %s>' % (self.USN, self.Location, self.Headers.__repr__())

        def __hash__(self):
            if self.USN is not None:
                return hash(self.USN)

            return hash(tuple(self.Headers.items()))

        def __eq__(self, other):
            if self is not None and other is None:
                return False

            if not isinstance(other, self.__class__):
                return False

            return hash(self) == hash(other)

        def __ne__(self, other):
            return not self.__eq__(other)

if __name__ == '__main__':
    # Searches for all SSDP services
    s = BasicSSDPServiceDiscoverer().discover()

    if s is not None:
        for r in s:
            print(r)