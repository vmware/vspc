"""A client to interact with the virtual serial port concentrator (vSPC) through
   its administrative interface, conventionally on TCP port 13371.

   Facilitates interactive connection to a single virtual machine serial port
   from your local terminal session.  If no port is identified on the command
   line, lists the serial ports available on a given vSPC.  An interactive
   session may be suspended using an escape character, with several useful
   commands available in that escape mode for closing or resuming the
   connection, sending the escape character to the serial port, or displaying
   information about the client's connection to the vSPC..
"""

import sys
import datetime
import asyncio
import termios
import tty
import telnet.connection
import vspc.admin_option
import vspc.lock
from optparse import OptionParser, OptionValueError

ADMIN_PORT = 13371

class VspcAdminClient(vspc.admin_option.VspcAdminOptionClient):
    """Provide a vSPC command-line client to query and connect to vSPC-managed
       serial ports."""

    ESCAPE_CHAR = b'\x1d'
    PROMPT = 'vspc-client> '

    def __init__(self):
        super().__init__()
        self.vm_port_id = None
        self.vspc_uri = 'telnet://127.0.0.1:13371' # XXX: Implement properly.
        self.saved_tcattr = None
        self.prompting = True
        self.cork_buffer = None
        self.connected_at_time = None
        self.last_tx_time = None
        self.tx_bytes = 0
        self.last_rx_time = None
        self.rx_bytes = 0

    # ---------------- vSPC admin protocol implementation

    @staticmethod
    def vm_port_display(vm_port_info):
        """Format a port identifier for display."""
        (vm_port_id, vm_name, vm_listening_uri) = vm_port_info
        # XXX: Sanitize for display: Only printable chars and no ':'.
        return '  '.join([vm_name, vm_port_id, vm_listening_uri])

    def received_vm_port_list(self, vm_port_list):
        """The admin server has provided a list of port identifiers."""
        # Sort by VM name.
        vm_port_list = sorted(vm_port_list, key=lambda e: e[1])
        if self.vm_port_id:
            print('The server did not recognize the port identifier.  Known ports:')
        else:
            print('List of known ports:')
            print('VM_NAME    VM_PORT_ID')
            print('=======    ==========')
        print('\n'.join(map(VspcAdminClient.vm_port_display, vm_port_list)))
        sys.exit(0)

    def connection_state_update(self, connected):
        """The admin server has processed our request to connect to a port and
           has informed us of success (connected == True) or failure."""
        if not self.vm_port_id:
            # We only expect connection state updates when we asked to connect
            # to a specific port.
            raise telnet.protocol.TelnetProtocolError(
                     'Server sent invalid connection state update.')
        if connected:
            self.connected_at_time = datetime.datetime.now()
            self.show_connection()
            self.set_prompting(False)

        else:
            # The named port was not known.  Let's show a list of available
            # ports.
            self.request_vm_port_list()

    def admin_server_is_available(self):
        """The admin server has become available.  We can now make requests."""
        if self.vm_port_id:

            # Attempt to connect to the named port.
            self.connect_to_vm_port(self.vm_port_id, vspc.lock.READWRITE)
        else:
            # No port ID given; Request a list of server names.
            self.request_vm_port_list()

    # -------------- Connection statistics/info

    @staticmethod
    def format_time(t):
        """Format a time for display, shown as absolute and relative number of
           seconds."""
        if not t:
            return '(never)'
        return '%s (%u sec ago)' % (
            str(t), (datetime.datetime.now() - t).seconds)

    @staticmethod
    def show_stats(label, time, num_bytes):
        """Output statistics related to data transmitted or received."""
        print(f'   {label}: {num_bytes:10,d} bytes total, most recent at {time}.')

    def show_info(self):
        """Report some information and statistics for the current
           connection."""
        connection_time = self.format_time(self.connected_at_time)
        print(f'Connected to "{self.vm_port_id}" on {self.vspc_uri} since {connection_time}.')
        self.show_stats('TX', self.format_time(self.last_tx_time), self.tx_bytes)
        self.show_stats('RX', self.format_time(self.last_rx_time), self.rx_bytes)
        print()

    # -------------- Local user-interface

    def show_connection(self):
        """Output a line indicating that we are connected to a port."""
        print(f'Connected to virtual serial port "{self.vm_port_id}". '
               'Escape char is ^].')

    def prompt(self):
        """Output the vSPC client's command prompt."""
        print(VspcAdminClient.PROMPT, end='', flush=True)

    def show_help(self):
        """Show informative help text."""
        print('vSPC client commands:\n'
              '    info          Display information for this connection.\n'
              '    close         Disconnect and exit the vSPC client.\n'
              '    continue      Return to interactive mode.\n'
              '    print-escape  Send the escape sequence to the serial port.\n')

    # ------------- Local input handling

    def set_stdin_raw(self, raw):
        """Set stdin to raw mode or restore it to cooked mode."""
        fd = sys.__stdin__.fileno()
        if raw and not self.saved_tcattr:
            self.saved_tcattr = termios.tcgetattr(fd)
            tty.setraw(fd, termios.TCSANOW)
        elif not raw and self.saved_tcattr:
            termios.tcsetattr(fd, termios.TCSANOW, self.saved_tcattr)
            self.saved_tcattr = None

    def set_corked(self, corked):
        """When corked, we don't output bytes received from the VM until
           we get "uncorked".  This is useful when we're showing a prompt and
           want to avoid scribbling on the screen."""
        if self.cork_buffer is not None and not corked:
            sys.stdout.buffer.write(self.cork_buffer)
            sys.stdout.buffer.flush()
            self.cork_buffer = None
        elif corked and self.cork_buffer is None:
            self.cork_buffer = bytearray()

    def set_prompting(self, prompting):
        """Set whether we are prompting the user for a local action (as opposed
           to when the user is interacting with the VM."""
        if prompting != self.prompting:
            self.set_stdin_raw(not prompting)
            self.set_corked(prompting)
            self.prompting = prompting

    def stdin_readable(self):
        """asyncio reports that stdin is readable.  We might want to enter
           "prompting" mode in response to the escape char, or leave
           "prompting" mode in response to the "continue" command, or forward
           data to the VM when we're not in "prompting" mode, or locally
           process a command when we are in "prompting" mode."""
        if self.prompting:
            # Fetch a line of text.  It should be a local command.
            in_bytes = sys.stdin.buffer.read1()
            if in_bytes == b'':
                # stdin reported EOF.  Treat it as the "quit" command.
                in_bytes = b'quit\n'
                sys.stdout.buffer.write(in_bytes)
            in_bytes = in_bytes.removesuffix(b'\n')

            # Command handling:
            if in_bytes in [b'close', b'exit', b'quit', b'q']:
                sys.exit(0)
            if in_bytes in [b'continue', b'cont', b'c']:
                self.show_connection()
                self.set_prompting(False)
            elif in_bytes in [b'print-escape', b'esc']:
                self.send(VspcAdminClient.ESCAPE_CHAR)
            elif in_bytes == b'info':
                self.show_info()
            elif in_bytes in [b'help', b'?']:
                self.show_help()
            elif in_bytes != b'':
                print('Unrecognized command.')
                self.show_help()
            if self.prompting:
                self.prompt()
        else:
            # Fetch a char at a time.  Send to VM if it's not the escape char.
            in_bytes = sys.stdin.buffer.read1(1)
            if in_bytes == VspcAdminClient.ESCAPE_CHAR:
                self.set_prompting(True)
                self.prompt()
            else:
                self.send(in_bytes)

    # ------------- In-band data to/from VM

    def send(self, b):
        self.last_tx_time = datetime.datetime.now()
        self.tx_bytes += len(b)
        self.conn.send_bytes(b)

    def print(self, b):
        self.last_rx_time = datetime.datetime.now()
        self.rx_bytes += len(b)
        if self.cork_buffer is not None:
            # Don't scribble to the screen when prompting for a command.
            self.cork_buffer += b
        else:
            sys.stdout.buffer.write(b)
            sys.stdout.buffer.flush()

async def main():
    """Connect to a vSPC's administrative interface and either request a port
       list or connect to an identified port.  Most of the work is done by the
       implementation of the VspcAdminClient telnet option."""

    parser = OptionParser(usage="usage: %prog [options] [vm_port_id]")
    parser.add_option("-a", "--admin-port", type='int', dest='admin_port', default=ADMIN_PORT,
                       help="VSPC Admin Port")
    parser.add_option("-s", dest='remote_host', default="localhost",
                       help="vSPC server to connect to (default localhost)")

    (options, args) = parser.parse_args()
    (reader, writer) = await asyncio.open_connection(options.remote_host, options.admin_port)
    t = telnet.connection.TelnetConnection(reader, writer) #, debug=True)
    vac = VspcAdminClient()
    t.add_option(vac)

    if len(args) > 2:
        parser.error("Expected 0 or 1 arguments, found %d" % len(args))

    vm_port_id = None
    if len(args) == 1:
        vm_port_id = args[0]
        vac.vm_port_id = vm_port_id

    # Asynchronously accept input from stdin.  This can either be local
    # vspc-client commands or input to be sent to the VM.
    asyncio.get_event_loop().add_reader(sys.__stdin__, VspcAdminClient.stdin_readable, vac)
    try:
        async for d in t.telnet_stream():
            if not isinstance(d, bytes):
                # We aren't expecting any Telnet Functions here.  If one slips
                # through, ignore it.
                continue
            # Received data from the VM.
            vac.print(d)

    except EOFError:
        pass
    finally:
        vac.set_prompting(True)
        print('Exiting.')

asyncio.run(main(), debug=False)
