"""
 Copyright (c) 2023 VMware, Inc.  All rights reserved. -- VMware Confidential
"""
"""The Telnet connection module encapsulates the current state of a Telnet link
   to another party.  This includes the set of options known by our side of the
   connection (subclasses of TelnetOption), which in turn carry the negotiation
   states of each of those options.

   The read/receive interface is provided by the "telnet_stream" async
   generator and through state changes and subnegotiations reported to the
   TelnetOption subclass instances registered to the connection.  The
   "telnet_stream" will produce bytes-like objects (for in-band data) and
   Function objects.

   The write/transmit interface is through the "send_bytes" method and through
   calling methods on the TelnetOption subclass instances registered to the
   connection.

   Clients of this module should not have to worry about the mechanics of the
   option negotiation process.  Data transfer at the level provided by this
   module will consist of actions such as:

   - Request the "BINARY" option.

   - If the other party requests the "COM-PORT" option, allow it, and notify me
     when it is active.

   - The other party sent us some in-band data.

   - We should send some in-band data to the other party.
"""

import telnet.protocol
import telnet.option

class TelnetConnection:
    """Manage a Telnet connection and the set of options in use."""
    def __init__(self, reader, writer, **kw):
        self.telnet = telnet.protocol.TelnetProtocol(reader, writer, **kw)
        # Set of options "in use" for this connection -- i.e. the options
        # known/available on this end of the connection.  The other party might
        # have declined/refused options, in which case they will still be in
        # this options set but will be inactive.
        #
        self.options = {}
        self.add_option(telnet.option.TelnetBinaryOption())
        self.add_option(telnet.option.TelnetSuppressGoAheadOption())

    def add_option(self, option):
        """Attaches the given option to this connection.  Future negotiation of
        that option will be automatically handled by the connection."""
        option.attach_to_connection(self)
        self.options[option.code] = option

    async def telnet_stream(self):
        """Async generator producing the stream of telnet data sent through this
        connection.  Produces only Telnet "function" objects and bytes-like
        object."""
        async for o in self.telnet.telnet_stream():
            if isinstance(o, telnet.protocol.OptionNegotiation):
                if not o.option_code in self.options:
                    self.add_option(telnet.option.TelnetUnknownOption(o.option_code))
                self.options[o.option_code].respond(o.action)
            elif isinstance(o, telnet.protocol.OptionSubnegotiation):
                if o.option_code in self.options:
                    self.options[o.option_code].subnegotiate(o.data)
                else:
                    print(f'Unhandled option subnegotiation: {o!r}')
            else:
                yield o

    def send_bytes(self, b):
        self.telnet.send_data(b)
