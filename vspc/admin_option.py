"""The vSPC Admin Option is a custom Telnet option used only for communication
   between a vSPC Client and a vSPC Server.  The option allows the server to
   communicate a list of known VM Ports to the client, and allows the client to
   connect/disconnect to specific VM Ports."""

import asyncio
import telnet.option

# XXX: Implement protocol negotiation.
GET_VM_PORT_LIST        = 0x10
VM_PORT_LIST            = 0x11
VM_PORT_SET_CONNECTION  = 0x20
VM_PORT_CONNECTED       = 0x21
VM_PORT_DISCONNECTED    = 0x22

class VspcAdminOption(telnet.option.TelnetOption):
    code = 0xe9
    name = 'VMWARE-VSPC-ADMIN'

    @staticmethod
    def encode(s):
        return s.encode(encoding='utf-8')

    @staticmethod
    def decode(b):
        return b.decode(encoding='utf-8')

class VspcAdminOptionServer(VspcAdminOption):
    """The "server" side of the vSPC Admin Option provides the facility to
       collect a VM Port list from the vSPC and serialize it to send to the
       client, as well as the facility used by the client to request
       connection/disconnection with a specific VM Port on the vSPC server."""
    def __init__(self):
        super().__init__()
        self.request(False, True)

    def vm_port_list(self):
        """The server overrides this method and uses it to return a VM Port
           list, which must be a list of tuples of (vm_port_id, vm_name,
           vm_listening_uri).  The vm_listening_uri is optional and may be
           None."""
        raise NotImplementedError('Server needs to provide a VM port list.')

    def connect_to_vm_port(self, vm_port, locking_mode):
        """The server overrides this to put into effect a client's request to
           connect to a specific VM Port on the vSPC server."""
        raise NotImplementedError('Server needs to provide port access.')

    @staticmethod
    def encode_vm_port_info(vm_port_info):
        """Given a VM Port info tuple, encode it for transmission in the
           VM_PORT_LIST subnegotiation."""
        vm_port_id = vm_port_info[0]
        vm_name = vm_port_info[1]
        vm_listening_uri = vm_port_info[2]
        if vm_name is None:
            vm_name = ''
        if vm_listening_uri is None:
            vm_listening_uri = ''
        return b'\0'.join(map(VspcAdminOption.encode,
                              (vm_port_id, vm_name, vm_listening_uri)))

    @staticmethod
    def encode_vm_port_list(vm_ports):
        """Given a VM Port info list, encode it for transmission in the
        VM_PORT_LIST subnegotiation."""
        return b'\0'.join(map(VspcAdminOptionServer.encode_vm_port_info,
                              vm_ports))

    def subnegotiate(self, subneg_data):
        """Handle option subnegotiation for the server side of the vSPC Admin
           option."""
        if subneg_data:
            subcmd = subneg_data[0]

            if subcmd == GET_VM_PORT_LIST and len(subneg_data) == 1:
                vm_port_blob = \
                    VspcAdminOptionServer.encode_vm_port_list(
                        self.vm_port_list())
                self.send_subnegotiation(bytes([VM_PORT_LIST]),
                                         vm_port_blob)
                return
            if subcmd == VM_PORT_SET_CONNECTION:
                if len(subneg_data) == 1:
                    vm_port_id = None
                    locking_mode = None
                    self.connect_to_vm_port(None, None)
                    self.send_subnegotiation(bytes([VM_PORT_DISCONNECTED]))
                    return
                elif len(subneg_data) > 2:
                    locking_mode = subneg_data[1]
                    vm_port_id = VspcAdminOption.decode(subneg_data[2:])
                    try:
                        self.connect_to_vm_port(vm_port_id, locking_mode)
                        ok = True
                    except PortNotFound as e:
                        ok = False
                    except PortAccessDenied as e:
                        ok = False

                    self.send_subnegotiation(bytes([VM_PORT_CONNECTED if ok else
                                                    VM_PORT_DISCONNECTED]))
                    return
        raise telnet.protocol.TelnetProtocolError(
                 'Client sent bad admin subnegotiation.')

class VspcAdminOptionClient(VspcAdminOption):
    """The "client" side of the vSPC Admin Option provides facilities to
       request a VM Port list from the vSPC server, with a hook point for when
       the server list is received, as well as providing the facility to
       request connection to a specific VM Port.  In-band telnet data
       corresponds to communication to/from the VM Port to which the client is
       connected."""

    @staticmethod
    def decode_vm_port_list(b):
        """Given a blob from the VM_PORT_LIST subnegotiation, deserialize it
           into a list of tuples of VM Port information."""
        if not b:
            return list()
        entries = b.split(b'\0')

        # Build a list of 3-tuples: (vm_port_id, vm_name, vm_listening_uri)
        if len(entries) % 3 != 0:
            raise telnet.protocol.TelnetProtocolError(
                      'Server sent bad port list length.')

        i = iter(map(VspcAdminOption.decode, entries))
        return zip(i, i, i)

    def should_accept(self, them):
        """If the other party reports that they are a vSPC Admin server, accept
           their request to use the option."""
        return them

    def admin_server_is_available(self):
        raise NotImplementedError(
            'Client needs to handle server becoming available.')

    def state_update(self, them, enabled):
        """The vSPC Admin option has been negotiated."""
        if them and enabled:
            self.admin_server_is_available()

    def request_vm_port_list(self):
        """Request that the server provides a list of known VM Ports."""
        self.send_subnegotiation(bytes([GET_VM_PORT_LIST]))

    def received_vm_port_list(self, vm_port_list):
        """Callback for when we have received a list of known VM Ports."""
        raise NotImplementedError('Client needs to handle VM Port list.')

    def connect_to_vm_port(self, vm_port, locking_mode):
        """Request that the server connect our in-band Telnet data to the given
           VM Port."""
        self.send_subnegotiation(bytes([VM_PORT_SET_CONNECTION]),
                                 bytes([locking_mode]),
                                 VspcAdminOption.encode(vm_port))

    def disconnect_from_vm_port(self):
        """Request that the server disconnect our in-band Telnet data so that
           any in-band Telnet data we send will be ignored, and no new in-band
           Telnet data should arrive after the request is acknowledged."""
        self.send_subnegotiation(bytes([VM_PORT_SET_CONNECTION]))

    def connection_state_update(self, connected):
        """Callback for when the server indicates that we have gained or lost
           our connection to the previously-requested VM Port."""
        pass

    def subnegotiate(self, subneg_data):
        """Handle option subnegotiation for the client side of the vSPC Admin
           option."""
        if subneg_data:
            subcmd = subneg_data[0]

            if subcmd in [VM_PORT_CONNECTED, VM_PORT_DISCONNECTED] and \
               len(subneg_data) == 1:
                self.connection_state_update(subcmd == VM_PORT_CONNECTED)
                return
            if subcmd == VM_PORT_LIST:
                self.received_vm_port_list(self.decode_vm_port_list(subneg_data[1:]))
                return
        raise telnet.protocol.TelnetProtocolError(
                 'Server sent bad admin subnegotiation.')
