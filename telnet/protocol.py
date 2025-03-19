"""The Telnet protocol module encapsulates the knowledge of RFC 854, RFC 855,
   et. seq.  All of the protocol encoding and decoding occurs inside this
   module.

   The primary read/receive interface is through the decoded tokens provided by
   the "telnet_stream" async iterator, which will produce bytes-like objects
   (for in-band data), OptionNegotiation objects, OptionSubnegotiation objects,
   and Function objects.

   The primary write/transmit interface is through the "send_data",
   "send_option_negotiation" and "send_option_subnegotiation" methods.

   Clients of this module should not have to worry about how an option
   negotiation or subnegotiation is transferred "on the wire", because it will
   all be handled internally and generically.  Data transfer at the level
   provided by this module will consist of messages such as:

   - The other party sent us a "WILL" for option <N>.

   - We should send the other party a "DONT" for option <N>.

   - The other party sent us a subnegotiation for option <N> with some
     associated subnegotiation data.

   - We should send the other party a subnegotiation for option <N> with some
     associated data.

   - The other party sent us some in-band data.

   - We should send some in-band data to the other party.

   Interpreting the option negotiation and subnegotiation data is the
   responsibility of clients of this module.
"""

import asyncio

class TelnetProtocolError(Exception):
    pass


class Function:
    # Telnet protocol constants defined in RFC 854 related to NVT "functions".
    _NOP  = 241 # No Operation
    # We don't care about the others...

    """RFC 854 describes "control functions" for a Network Virtual Terminal
    (NVT), such as Interrupt Process (IP), Abort Output (AO), etc."""
    def __init__(self, function):
        self.function = function

    def __repr__(self):
        return 'Telnet function 0x%02x' % self.function

    def __str__(self):
        return 'IAC %02x' % self.function

    def __bytes__(self):
        return TelnetProtocol._IAC + bytes([self.function])


class OptionNegotiation:
    """RFC 854 defines the basic negotiation for an option, which consists of
    messages carrying a paired "action" (DO/DONT/WILL/WONT) and an option
    identifier."""

    # Telnet protocol constants defined in RFC 854 related to option
    # negotiation.
    DONT = 254 # Reject a requested option
    DO   = 253 # Request an option
    WONT = 252 # Decline an offered option
    WILL = 251 # Offer an option
    _ACTIONS = {
        WILL: 'WILL',
        WONT: 'WONT',
        DO:   'DO',
        DONT: 'DONT'
    }

    def __init__(self, action, option_code):
        assert action in OptionNegotiation._ACTIONS
        self.action = action
        self.option_code = option_code

    def __str__(self):
        return 'IAC ' + self.__repr__()

    def __repr__(self):
        try:
            action_str = OptionNegotiation._ACTIONS[self.action]
        except KeyError:
            action_str = self.action.hex(' ')

        return '%s %s' % (
            action_str,
            TelnetProtocol.option_code_repr(self.option_code)
        )

    def __bytes__(self):
        return TelnetProtocol._IAC + bytes([self.action, self.option_code])


class OptionSubnegotiation:
    """RFC 854 defines the protocol representation for Option Subnegotiation,
       which is further explained in RFC 855.  After the use of an option is
       negotiated (see OptionNegotiation), arbitrary data may be communicated
       -- associated with the option identifier -- to allow more fine-grained
       control of the option between the endpoints."""
    def __init__(self, option_code, data):
        self.option_code = option_code
        self.data = data

    def __str__(self):
        return 'IAC SB %s escaped(%s) IAC SE' % (
            TelnetProtocol.option_code_repr(self.option_code),
            self.data.hex(' ')
        )

    def __repr__(self):
        return '%s subnegotiation: %s' % (
            TelnetProtocol.option_code_repr(self.option_code),
            repr(self.data)
        )

    def __bytes__(self):
        return TelnetProtocol._IAC + \
               TelnetProtocol._SB + \
               bytes([self.option_code]) + \
               self.data.replace(TelnetProtocol._IAC, TelnetProtocol._IAC + TelnetProtocol._IAC) + \
               TelnetProtocol._IAC + \
               TelnetProtocol._SE


class TelnetProtocol:
    """This class knows only about RFC 854 and RFC 855.  It handles the generic
       parts of option negotiation and subnegotiation, escaping and
       unescaping."""

    # Telnet protocol constants defined in RFC 854.
    _IAC = bytes([255]) # "Interpret As Command"
    _SE  = bytes([240]) # Option Subnegotiation End
    _SB  = bytes([250]) # Option Subnegotiation Begin

    # Dictionary of all registered Telnet option names, indexed by option code.
    optionNames = {}

    # Stream identifier for debugging.
    debug_index = 0

    def __init__(self, reader, writer, debug=False):
        self.decoder = TelnetProtocolStreamDecoder(reader)
        self._writer = writer
        self.debug = debug
        if debug:
            self.my_debug_index = TelnetProtocol.debug_index
            TelnetProtocol.debug_index += 1

            self.debug_tx_queue = asyncio.Queue()
            # XXX: This task needs to be canceled when the protocol instance
            #      goes away.
            asyncio.create_task(TelnetProtocolQueueDecoder(self.debug_tx_queue).log_all(f'TX({self.my_debug_index:d})'))

    @staticmethod
    def register_option(option_code, cls):
        if option_code in TelnetProtocol.optionNames:
            assert TelnetProtocol.optionNames[option_code] == cls.name
        else:
            TelnetProtocol.optionNames[option_code] = cls.name

    @staticmethod
    def option_code_repr(option_code):
        try:
            return TelnetProtocol.optionNames[option_code]
        except KeyError:
            pass
        return f'UNKNOWN-OPTION-{option_code:02x}'

    def _write(self, *args):
        """Send a sequence of bytes to the other party."""
        tx = b''.join(map(bytes, args))
        self._writer.write(tx)
        if self.debug:
            self.debug_tx_queue.put_nowait(tx)

    def send_data(self, data):
        """Send raw data.  Escape IAC."""
        self._write(data.replace(TelnetProtocol._IAC, TelnetProtocol._IAC + TelnetProtocol._IAC))

    def send_option_negotiation(self, option_code, action):
        self._write(OptionNegotiation(action, option_code))

    def send_option_subnegotiation(self, option_code, *args):
        self._write(OptionSubnegotiation(option_code, b''.join(args)))

    def start_tls(self, sslcontext, **kwargs):
        self._writer.start_tls(sslcontext, **kwargs)

    async def telnet_stream(self):
        async for o in self.decoder:
            if self.debug:
                print(f'RX({self.my_debug_index:d}): {o!s}')
            yield o


class TelnetProtocolDecoder:
    def __init__(self):
        self.buf = b''
        self.offset = 0
        self.buffer_len = 0

    async def _read(self):
        """Subclasses must implement this to obtain some number of bytes from a
           data source, waiting if necessary.  EOFError must be raised if there
           is no prospect of any more bytes arriving."""
        raise NotImplementedError

    async def ensure_byte(self):
        """The caller requires at least one byte in our buffer.  Wait if
           necessary to obtain at least one byte."""
        if self.offset == self.buffer_len:
            self.buf = await self._read()
            if not self.buf:
                raise EOFError('Socket read encountered end-of-file.')
            self.buffer_len = len(self.buf)
            self.offset = 0

    async def byte(self):
        """Returns the value of the next byte in the stream."""
        await self.ensure_byte()
        c = self.buf[self.offset]
        self.offset += 1
        return c

    async def until_IAC(self):
        """Returns a bytes-like object containing one or more bytes according
           to the following rules:

            1. If the first byte is an IAC, that will be the only byte
               returned.
            2. Otherwise, return as many non-IAC bytes as possible.
        """
        await self.ensure_byte()
        o = self.offset
        end_index = self.buf.find(TelnetProtocol._IAC, o)
        if end_index < 0:
            # Not found, return the remainder of the buffer.
            end_index = self.buffer_len
        elif end_index == o:
            # We are at an IAC.  Consume and return it.
            end_index = end_index + 1
        # Consume and return the appropriate piece of buffer.
        self.offset = end_index
        return self.buf[o:end_index]

    def __aiter__(self):
        """The object is its own async iterator."""
        return self

    async def __anext__(self):
        """Async iterator to produce a decoded stream of Telnet events.  These
           might consist of bytes-like objects for data being sent through the
           Telnet connection, as well as Function, OptionNegotiation and
           OptionSubnegotiation objects representing Telnet protocol activity.
        """
        while True:
            buf = await self.until_IAC()
            if buf != TelnetProtocol._IAC:
                return buf

            # Received an IAC.  Might be an option negotiation (DO/DONT/WILL/WONT),
            # subnegotiation (SB...SE), NOP, etc.
            command = await self.byte()

            if command == Function._NOP:
                # NOP is ignored.
                continue

            if 0xf2 <= command <= 0xf9:
                # Data Mark, BRK, IP, AO, AYT, EC, EL, GA.
                return Function(command)

            if command in OptionNegotiation._ACTIONS:
                # DO/DONT/WILL/WONT.
                return OptionNegotiation(command, await self.byte())

            if command == TelnetProtocol._IAC[0]:
                # IAC+IAC decodes to IAC.
                return TelnetProtocol._IAC

            if command == TelnetProtocol._SE[0]:
                raise TelnetProtocolError('Unexpected IAC+SE')

            if command == TelnetProtocol._SB[0]:
                break

            # Any unrecognized command code should be treated as NOP and
            # ignored.

        # Option subnegotiation.  Accumulate data until IAC+SE.
        opt_subneg_data = bytearray()
        while True:
            buf = await self.until_IAC()
            if buf == TelnetProtocol._IAC:
                # Received an IAC within option subnegotiation.
                buf = bytes([await self.byte()])
                if buf == TelnetProtocol._IAC:
                    # Unescape IAC+IAC within option subnegotiation.
                    opt_subneg_data += TelnetProtocol._IAC
                    continue

                if buf == TelnetProtocol._SE:
                    # End of Option Subnegotiation.
                    break

                raise TelnetProtocolError(f'Unexpected IAC+{buf[0]:02x} in option subnegotiation')

            opt_subneg_data += buf

        if len(opt_subneg_data) < 1:
            raise TelnetProtocolError('Missing option subnegotiation data.')

        return OptionSubnegotiation(opt_subneg_data[0], opt_subneg_data[1:])


class TelnetProtocolStreamDecoder(TelnetProtocolDecoder):
    """A Telnet decoder which sources its data from an asyncio.StreamReader."""
    def __init__(self, reader):
        super().__init__()
        self._reader = reader

    async def _read(self):
        try:
            b = await self._reader.read(2048)
        except BrokenPipeError as bpe:
            raise EOFError("Socket pipe closed") from bpe
        except ConnectionResetError as cre:
            raise EOFError("Socket connection reset") from cre
        return bytes(b)


class TelnetProtocolQueueDecoder(TelnetProtocolDecoder):
    """A Telnet decoder which sources its data from an asyncio.Queue of
       bytes-like objects."""
    def __init__(self, queue):
        super().__init__()
        self.queue = queue

    async def _read(self):
        qi = await self.queue.get()
        # It's not _really_ done yet, but oh well...
        self.queue.task_done()
        return qi

    async def log_all(self, prefix):
        async for o in self:
            print(f'{prefix}: {o!s}')


class TelnetProtocolTest(TelnetProtocolDecoder):
    """A unit-test decoder which sources its data from a static bytes-like
       object, combined with a test routine which confirms that the decoder's
       output is as expected for a given test case."""
    def __init__(self, data):
        super().__init__()
        self.test_data = data

    async def _read(self):
        d = self.test_data
        self.test_data = None
        return d

    async def expect(self, output):
        print(f'Expecting {output!r}')
        index = 0
        try:
            async for o in self:
                if bytes(o) != bytes(output[index]):
                    print(f'Got <{o!s}>, expecting <{output[index]!s}>')
                assert bytes(o) == bytes(output[index])
                index += 1
        except EOFError:
            pass
        except TelnetProtocolError:
            assert output[index] == TelnetProtocolError
            index += 1
        assert index == len(output)

    @staticmethod
    def run_decoder_test():
        IAC = TelnetProtocol._IAC
        SB = TelnetProtocol._SB
        SE = TelnetProtocol._SE
        NOP = bytes([Function._NOP])
        AYT = bytes([246])
        for in_data, out_stream in (
            (b'123', [b'123']),
            (b'123' + b'456', [b'123456']),
            (b'123' + IAC + NOP + b'456', [b'123', b'456']),
            # The next case could fail if the decoder gets optimized to try to
            # consolidate IAC+IAC onto surrounding data, but it's an uncommon
            # case so optimizing it is unlikely.
            (b'123' + IAC + IAC + b'456', [b'123', b'\xff', b'456']),
            (b'123' + IAC + AYT + b'456', [b'123', Function(AYT[0]), b'456']),
            (b'123' + IAC + b'456', [b'123', b'56']), # Note: IAC b'4' == NOP
            (b'1' + IAC + bytes([251, 123]) + b'2',
                [b'1', OptionNegotiation(OptionNegotiation.WILL, 123), b'2']),
            (b'1' + IAC + SB + bytes([123, 1, 2]) + IAC + SE + b'2',
                [b'1', OptionSubnegotiation(123, bytes([1, 2])), b'2']),
            (b'1' + IAC + SB + bytes([123, 1]) + IAC + IAC + bytes([2]) + IAC + SE + b'2',
                [b'1', OptionSubnegotiation(123, bytes([1, 255, 2])), b'2']),
            (b'1' + IAC + SB + bytes([123]) + IAC + IAC + bytes([2]) + IAC + SE + b'2',
                [b'1', OptionSubnegotiation(123, bytes([255, 2])), b'2']),
            (b'1' + IAC + SB + bytes([123, 1]) + IAC + IAC + IAC + SE + b'2',
                [b'1', OptionSubnegotiation(123, bytes([1, 255])), b'2']),
            (b'1' + IAC + SB + bytes([123, 1]) + IAC + IAC + SE + IAC + SE + b'2',
                [b'1', OptionSubnegotiation(123, bytes([1, 255, SE[0]])), b'2']),
            (b'123' + IAC + SB + b'1' + IAC + SB, [b'123', TelnetProtocolError]),
            (b'123' + IAC + SE, [b'123', TelnetProtocolError]),
        ):
            asyncio.run(TelnetProtocolTest(in_data).expect(out_stream))


if __name__ == "__main__":
    TelnetProtocolTest.run_decoder_test()
    print('Test complete.')
