# **********************************************************
# Copyright (c) 2023 VMware, Inc.  All rights reserved. -- VMware Confidential
# **********************************************************

"""Accepts a connection from a VMware virtual serial port (or other compatible
   endpoint) and displays received in-band data as well as COM port parameters
   (baud rate, data size, parity, stop bits)."""

import asyncio
import telnet.connection
import telnet.option

class NoisyTelnetComPortOption(telnet.option.TelnetComPortOption):
    """Hooks notifications for changes to serial port parameters received
       through the Telnet COM-PORT option and outputs informative messages to
       stdout."""

    parityStr = {
        1: 'None',
        2: 'Odd',
        3: 'Even',
        4: 'Mark',
        5: 'Space',
    }
    stopSizeStr = {
        1: '1',
        2: '2',
        3: '1.5',
    }

    def set_baud_rate(self, baud_rate):
        super().set_baud_rate(baud_rate)
        print(f'Baud rate set to {baud_rate}.')

    def set_data_size(self, data_size):
        super().set_data_size(data_size)
        print(f'Data size set to {data_size}.')

    def set_parity(self, parity):
        super().set_parity(parity)
        try:
            p = self.parityStr[parity]
        except KeyError:
            p = f'<{parity:02x}>'
        print(f'Parity set to {p}.')

    def set_stop_size(self, stop_size):
        super().set_stop_size(stop_size)
        try:
            s = self.stopSizeStr[stop_size]
        except KeyError:
            s = f'<{stop_size:02x}>'
        print(f'Stop size set to {s}.')

async def telnet_accept(reader, writer):
    """A serial port connection has been received.  Start logging its in-band
       data and serial connection parameters."""
    try:
        t = telnet.connection.TelnetConnection(reader, writer, debug=True)
        t.add_option(NoisyTelnetComPortOption())
        t.add_option(telnet.option.TelnetVMwareExtensionOptionServer('serial-diagnostics.py'))
        async for o in t.telnet_stream():
            print(f'Received: {o!s}')
    except EOFError:
        pass
    finally:
        writer.close()
    try:
        await writer.drain()
        await writer.wait_closed()
    except ConnectionResetError:
        pass
    except BrokenPipeError:
        pass

async def main():
    """Listen for incoming connections."""
    server = await asyncio.start_server(
        telnet_accept, '127.0.0.1', 13370)

    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    print(f'Serving on {addrs}')

    async with server:
        await server.serve_forever()

asyncio.run(main())
