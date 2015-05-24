#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket as s
import time
import re
from uuid import uuid4
from abc import ABCMeta, abstractmethod
from requests.structures import CaseInsensitiveDict

class SSDPServiceDiscoverer(object):
    """An implementation of the service discovery process as described by SSDP, 
    the Simple Service Discovery Protocol. This can be used to discover present 
    UPnP-Services in the local network."""

    __metaclass__ = ABCMeta

    _SSDP_INFO = {'ssdp_address': '239.255.255.250', 'ssdp_port': 1900}
    _SSDP_DISCOVERY_DEFAULT_TIMEOUT = 1 # 1 second timeout
    _SSDP_DISCOVERY_DEFAULT_RETRY_DELAY = 0.01 # Approx 10ms
    _SSDP_DISCOVERY_DEFAULT_TRIES_COUNT = 2 # Number of attempts
    _SSDP_DISCOVERY_DEFAULT_MX = 3 # MX = 3
    _SSDP_DISCOVERY_DEFAULT_TTL = 10 # TTL = 10
    _SSDP_DISCOVERY_RECV_BUFFER_SIZE = 1 << 13 # Buffer size is 8192 bytes. Longer recv. messages might be broken.

    _CRLF = "\r\n"

    _MSEARCH_REQUEST_TEMPLATE = _CRLF.join([
        'M-SEARCH * HTTP/1.1',
        'HOST: {ssdp_address}:{ssdp_port}',
        'MAN: "ssdp:discover"',
        'MX: {mx}',
        'ST: {st}',
        '', # Terminate with two CRLF
        '',
    ])

    def discover(self, serviceType, timeout=_SSDP_DISCOVERY_DEFAULT_TIMEOUT, numTries=_SSDP_DISCOVERY_DEFAULT_TRIES_COUNT, retryDelaySeconds=_SSDP_DISCOVERY_DEFAULT_RETRY_DELAY, mx=_SSDP_DISCOVERY_DEFAULT_MX, ttl=_SSDP_DISCOVERY_DEFAULT_TTL, uuid=None):
        """Perform a service discovery in the local network.

        :param str serviceType: The ST service type descriptor of the service to discover.
        :param int timeout: The time to wait for discovery replies.
        :param int numTries: The number of times to emit a M-SEARCH request.
        :param float retryDelaySeconds: The time in seconds to wait before emitting the next M-SEARCH request.
        :param mx: The M-SEARCH request MX parameter.
        :param int ttl: The TTL of the broadcast message.
        :param uuid: The unique identifier of the search to use, or None if a random id should be generated.
        """

        # Use provided uuid or generate a new one if needed
        uuid = uuid or uuid4()

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

            # Try to receive the resposes
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
        """Initialize the BasicSSDPServiceDiscoverer"""
        super(BasicSSDPServiceDiscoverer, self).__init__()

        self._responseCache = {}

    def _handleResponse(self, response, uuid):
        """Parses all responses received for a discovery and returns a list of SSDPResponse.

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

        resps = set()

        # Parse all responses
        for r in self._responseCache[uuid]:
            resps.add(BasicSSDPServiceDiscoverer.SSDPResponse(r))

        # Remove entry from cache
        del self._responseCache[uuid]

        return resps

    class SSDPResponse(object):
        """A container class for received SSDP responses."""

        def __init__(self, response):
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
