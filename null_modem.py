# **********************************************************
# Copyright (c) 2023 VMware, Inc.  All rights reserved. -- VMware Confidential
# **********************************************************

"""Accepts connections from VMware virtual serial ports (or other compatible
   endpoints) and sends all in-band data from each port to each other port.
   There is no checking of serial port parameters, so this somewhat-unusual
   "null modem" allows communication between endpoints with differing baud
   rates, data sizes, etc.

   Although intended to connect just two ports at a time, it imposes no limit
   on the number of ports -- just be careful to avoid creating feedback loops
   through the attached endpoints."""

import asyncio
import telnet.protocol
import telnet.connection

connections = []

async def telnet_accept(reader, writer):
    """A serial port connection has been received.  Add it to the list of
       connections and forward its data to all other connections."""
    try:
        t = telnet.connection.TelnetConnection(reader, writer, debug=False)
        connections.append(t)
        async for o in t.telnet_stream():
            if not isinstance(o, bytes):
                # We aren't expecting any Telnet Functions here.  If one slips
                # through, ignore it.
                continue
            for other in connections:
                if other != t:
                    other.telnet.send_data(o)
    except EOFError:
        pass
    finally:
        connections.remove(t)
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
