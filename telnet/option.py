"""The Telnet option module encapsulates the essence of a Telnet "option"
   (described in RFC 855), including the current state of the option within a
   connection as well as the mechanics of negotiating that option (described in
   RFC 1143).

   Trivial implementations are provided for the Telnet BINARY option (RFC 856)
   and the SUPPRESS-GO-AHEAD option (RFC 858), both of which are assumed to
   always be in effect on both sides of every Telnet connection managed by this
   package.

   An implementation is provided for the Telnet COM-PORT option (RFC 2217),
   illustrating how to manage negotiation and subnegotiation and how to
   convert these into notifications which subclasses can use for
   application-specific purposes.
"""

from enum import IntEnum, auto
import secrets
import struct
import urllib.parse
import telnet.protocol

class TelnetOptionQState(IntEnum):
    """Used to track the state of an option on either end of the connection.
       See to RFC 1143 for background on the state-tracking involved.  Note
       that us/usq and them/themq are each combined into six-choice states.

       Please read RFC 1143 before modifying the option negotiation
       request/response implementation below."""
    NO = auto()
    YES = auto()
    WANTNO_EMPTY = auto()
    WANTNO_OPPOSITE = auto()
    WANTYES_EMPTY = auto()
    WANTYES_OPPOSITE = auto()

WILL = telnet.protocol.OptionNegotiation.WILL
WONT = telnet.protocol.OptionNegotiation.WONT
DO    = telnet.protocol.OptionNegotiation.DO
DONT  = telnet.protocol.OptionNegotiation.DONT

class TelnetOption:
    """Instances of TelnetOption are used to track the state of an option
       w.r.t. their associated Telnet connection.

       Ideally, subclasses of TelnetOption will provide the definition for a
       single Telnet option, all of the logic to decode and encode the relevant
       messages in subnegotiation, and any logic which is strictly "internal"
       to the workings of the option.  These subclasses can then themselves
       be further subclassed and specialized with behaviors required by
       whichever function is using the option"""
    code: int = None
    name: str = None
    us:   TelnetOptionQState
    them: TelnetOptionQState

    def __init_subclass__(cls):
        """Ensure that the Telnet protocol "knows" about each option
           subclass."""
        super().__init_subclass__()
        telnet.protocol.TelnetProtocol.register_option(cls.code, cls)

    def __init__(self):
        # Track the negotiation state (WILL/WONT/DO/DONT) for the option on
        # each side of the connection.
        self.us = TelnetOptionQState.NO
        self.them = TelnetOptionQState.NO
        self.conn = None
        self.queued_response = None

    def attach_to_connection(self, conn):
        self.conn = conn
        if self.queued_response:
            # Negotiation was started by our side before we were associated
            # with a connection.  Send the pending negotiation message.
            self.conn.telnet.send_option_negotiation(self.code, self.queued_response)
            self.queued_response = None

    # =========== Option negotiation hooks ===========

    def should_accept(self, unused_them):
        """Options are rejected by default.  Subclasses implementing a specific
           option should override this to return True iff we agree to use the
           option as described.  Implementations will often just "return True"
           or "return them", for example."""
        return False

    def state_update(self, unused_them, unused_enabled):
        """Option subclasses may hook this as an opportunity to take action
           when the option is either activated or deactivated for one party."""

    # =========== Generic option negotiation ===========

    @staticmethod
    def _rfc1143_q_request(state, enabled):
        """A caller has asked us to activate or deactivate an option.  Follow
           the state diagrams in RFC 1143 section 7 to determine a request to
           send to the other party (if needed) and the subsequent state."""
        response = None
        if enabled: # RFC 1143: "If we decide to ask [them] to enable..."
            if state == TelnetOptionQState.NO:
                state = TelnetOptionQState.WANTYES_EMPTY
                response = True
            elif state == TelnetOptionQState.WANTNO_EMPTY:
                state = TelnetOptionQState.WANTNO_OPPOSITE
            elif state == TelnetOptionQState.WANTYES_OPPOSITE:
                state = TelnetOptionQState.WANTYES_EMPTY
        else: # RFC 1143: "If we decide to ask [them] to disable..."
            if state == TelnetOptionQState.YES:
                state = TelnetOptionQState.WANTNO_EMPTY
                response = False
            elif state == TelnetOptionQState.WANTNO_OPPOSITE:
                state = TelnetOptionQState.WANTNO_EMPTY
            elif state == TelnetOptionQState.WANTYES_EMPTY:
                state = TelnetOptionQState.WANTYES_OPPOSITE

        return (state, response)

    def request(self, them, enabled):
        """A caller has asked us to activate or deactivate an option, either
           for "us" or for "them"."""
        if them:
            # RFC 1143: "If we decide to ask [them] to enable:"
            #           "If we decide to ask [them] to disable:"
            # Handle the option on their side as described in RFC 1143 section 7.
            init_state = self.them
            (new_state, response) = \
                TelnetOption._rfc1143_q_request(self.them, enabled)
            if response != None:
                response = DO if response else DONT
            self.them = new_state
        else:
            # RFC 1143: "We handle the option on our side by the same
            #           procedures, with DO-WILL, DONT-WONT, [them-us]
            #           swapped."
            init_state = self.us
            (new_state, response) = \
                TelnetOption._rfc1143_q_request(self.us, enabled)
            if response != None:
                response = WILL if response else WONT
            self.us = new_state

        if response:
            if self.conn:
                self.conn.telnet.send_option_negotiation(self.code, response)
            else:
                # Negotiation was started by our side before we were associated
                # with a connection.  Defer sending until we have a connection.
                self.queued_response = response

        # RFC 1143: "An option is enabled if and only if its state is YES."
        # If the state has changed, notify.
        active = new_state == TelnetOptionQState.YES
        if (init_state == TelnetOptionQState.YES) != active:
            self.state_update(them, active)

    def _rfc1143_q_respond(self, state, activate, them):
        """The other party has asked us to activate or deactivate an option.
           Follow the state diagrams in RFC 1143 section 7 to determine a
           response (if needed) and the subsequent state."""
        response = None
        if activate: # RFC 1143: "Upon receipt of WILL [or DO]..."
            if state == TelnetOptionQState.NO:
                if self.should_accept(them):
                    state = TelnetOptionQState.YES
                    response = True
                else:
                    response = False
            elif state == TelnetOptionQState.WANTNO_EMPTY:
                # RFC 1143: "Error: DONT answered by WILL."
                state = TelnetOptionQState.NO
            elif state == TelnetOptionQState.WANTNO_OPPOSITE:
                # RFC 1143: "Error: DONT answered by WILL."
                state = TelnetOptionQState.YES
                # RFC 1143 says "q=EMPTY", but the "q" state is meaningless.
            elif state == TelnetOptionQState.WANTYES_EMPTY:
                state = TelnetOptionQState.YES
            elif state == TelnetOptionQState.WANTYES_OPPOSITE:
                state = TelnetOptionQState.WANTNO_EMPTY
                response = False
        else: # RFC 1143: "Upon receipt of WONT [or DONT]..."
            if state == TelnetOptionQState.YES:
                state = TelnetOptionQState.NO
                response = False
            elif state == TelnetOptionQState.WANTNO_EMPTY:
                state = TelnetOptionQState.NO
            elif state == TelnetOptionQState.WANTNO_OPPOSITE:
                # RFC 1143 says "q=NONE" here but clearly intended "q=EMPTY".
                state = TelnetOptionQState.WANTYES_EMPTY
                response = True
            elif state == TelnetOptionQState.WANTYES_EMPTY:
                state = TelnetOptionQState.NO
            elif state == TelnetOptionQState.WANTYES_OPPOSITE:
                state = TelnetOptionQState.NO
                # RFC 1143 says "q=NONE", but the "q" state is meaningless.

        return (state, response)

    def respond(self, action):
        """The other party has asked us to activate or deactivate an option,
           either for "us" or for "them"."""
        activate = action in [WILL, DO]
        them = action in [WILL, WONT]

        if them:
            # Handle the option on their side as described in RFC 1143 section 7.
            init_state = self.them
            (new_state, response) = \
                self._rfc1143_q_respond(init_state, activate, them)
            self.them = new_state
            if response != None:
                response = DO if response else DONT
        else:
            # RFC 1143: "We handle the option on our side by the same
            #           procedures, with DO-WILL, DONT-WONT, [them-us]
            #           swapped."
            init_state = self.us
            (new_state, response) = \
                self._rfc1143_q_respond(init_state, activate, them)
            self.us = new_state
            if response != None:
                response = WILL if response else WONT

        if response:
            self.conn.telnet.send_option_negotiation(self.code, response)

        # RFC 1143: "An option is enabled if and only if its state is YES."
        # If the state has changed, notify.
        active = new_state == TelnetOptionQState.YES
        if (init_state == TelnetOptionQState.YES) != active:
            self.state_update(them, active)

    # =========== Option subnegotiation ===========

    def subnegotiate(self, subneg_data):
        """Subclasses may need to handle a received option subnegotiation
           packet."""

    def send_subnegotiation(self, *args):
        """Construct and send a subnegotiation to the other party."""
        self.conn.telnet.send_option_subnegotiation(self.code, *args)


class TelnetUnknownOption(TelnetOption):
    """Instances of the Telnet "unknown" option are used for options which are
       not known or not in use on the connection."""
    def __init__(self, option_code):
        super().__init__()
        self.code = option_code

    def should_accept(self, unused_them):
        return False


class TelnetBinaryOption(TelnetOption):
    """The Telnet BINARY option is assumed to always be active, but must still
       be negotiated."""
    code = 0x00
    name = 'BINARY'

    def should_accept(self, unused_them):
        """Always accept BINARY, on both sides."""
        return True


class TelnetSuppressGoAheadOption(TelnetOption):
    """The Telnet SGA option is an anachronism.  Supporting it is
       zero-effort."""
    code = 0x03
    name = 'SGA'

    def should_accept(self, unused_them):
        """Always accept SGA, on both sides."""
        return True


class TelnetAuthenticationOption(TelnetOption):
    """Telnet AUTHENTICATION is described in RFC 2941.  We only accept the SSL
       authentication type, which appears to be largely undocumented.  The best
       reference is probably the netkit-telnet-ssl sources at
       https://sources.debian.org/src/netkit-telnet-ssl/ .

       This implementation can act as either the client or server.

       Either pass an SSLContext into the constructor or produce it on demand
       by overridding generate_ssl_context in a subclass."""
    code = 0x25
    name = 'AUTHENTICATION'

    AUTH_CMD_IS = bytes([0])
    AUTH_CMD_SEND = bytes([1])
    AUTH_CMD_REPLY = bytes([2])

    AUTH_TYPE_SSL = bytes([7])
    AUTH_TYPE_SSL_MODIFIERS = bytes([0]) # Modifiers ignored.

    AUTH_TYPE_PAIR_SSL = AUTH_TYPE_SSL + AUTH_TYPE_SSL_MODIFIERS

    AUTH_SSL_START = bytes([1])
    AUTH_SSL_ACCEPTED = bytes([2])

    def __init__(self, server = True, ssl_context = None):
        super().__init__()
        self.is_server = server
        self.auth_type = None
        self.ssl_context = ssl_context

    def should_accept(self, them):
        """Accept the other side's use of AUTHENTICATION."""
        return them == self.is_server

    def state_update(self, them, enabled):
        """When the other side accepts authentication, send our offer."""
        super().state_update(them, enabled)
        if them and self.is_server and enabled:
            self.auth_type = TelnetAuthenticationOption.AUTH_TYPE_PAIR_SSL
            self.send_subnegotiation(
                TelnetAuthenticationOption.AUTH_CMD_SEND,
                self.auth_type
            )

    def generate_ssl_context(self):
        """Subclasses should build an SSL context for us."""
        raise NotImplementedError('No SSL context available.')

    @staticmethod
    def find_auth_type(data):
        """Look for our prefered AUTH_TYPE_PAIR_SSL in the given list of
           authentication types from the other side.  If that exact type isn't
           present, accept any AUTH_TYPE_SSL pair.  Return None if there was
           really nothing suitable."""
        best = None
        for i in range(0, len(data), 2):
            if data[i:i+1] == TelnetAuthenticationOption.AUTH_TYPE_SSL:
                if data[i+1:i+2] == \
                   TelnetAuthenticationOption.AUTH_TYPE_SSL_MODIFIERS:
                    # Perfect match.  Return it now.
                    return data[i:i+2]
                # Right type, but modifiers aren't what we expect.  Hope we see
                # better... and otherwise, hope that what we found here is good
                # enough.
                best = data[i:i+2]
        return best

    def subnegotiate(self, subneg_data):
        """When the other side request to start SSL, accept it and immediately
           switch to TLS."""
        switch_to_tls = False
        if not self.is_server and \
           subneg_data[0:1] == TelnetAuthenticationOption.AUTH_CMD_SEND:
            self.auth_type = self.find_auth_type(subneg_data[1:])
            if self.auth_type:
                # Elect the chosen auth_type.
                self.send_subnegotiation(
                    TelnetAuthenticationOption.AUTH_CMD_IS,
                    self.auth_type,
                    TelnetAuthenticationOption.AUTH_SSL_START)
            else:
                # Nothing suitable; Decline.
                self.send_subnegotiation(
                    TelnetAuthenticationOption.AUTH_CMD_IS,
                    bytes([0, 0]))
        if self.is_server and subneg_data[0:4] == (
           TelnetAuthenticationOption.AUTH_CMD_IS +
           self.auth_type +
           TelnetAuthenticationOption.AUTH_SSL_START):
            self.send_subnegotiation(
                TelnetAuthenticationOption.AUTH_CMD_REPLY,
                self.auth_type,
                TelnetAuthenticationOption.AUTH_SSL_ACCEPTED
            )
            switch_to_tls = True
        if not self.is_server and subneg_data[0:4] == (
            TelnetAuthenticationOption.AUTH_CMD_REPLY +
            self.auth_type +
            TelnetAuthenticationOption.AUTH_SSL_ACCEPTED):
            switch_to_tls = True

        if switch_to_tls:
            # Immediately upgrade to TLS.
            if not self.ssl_context:
                self.ssl_context = self.generate_ssl_context()
            self.conn.telnet.start_tls(self.ssl_context)


class TelnetComPortOption(TelnetOption):
    """The Telnet COM-PORT (or COMPORT) option allows for physical serial port
       parameters to be set and queried through a Telnet channel.  See RFC 2217
       for details."""
    code = 0x2c
    name = 'COM-PORT'

    def __init__(self):
        super().__init__()
        self.baud_rate = None
        self.data_size = None
        self.parity = None
        self.stop_size = None

    def should_accept(self, them):
        """Accept the other side's use of COMPORT.  We are the "Access Server",
           in RFC 2217 parlance."""
        return them

    def set_baud_rate(self, baud_rate):
        """The client has sent a request to change the baud rate."""
        self.baud_rate = baud_rate

    def set_data_size(self, data_size):
        """The client has sent a request to change the data size."""
        self.data_size = data_size

    def set_parity(self, parity):
        """The client has sent a request to change the parity option."""
        self.parity = parity

    def set_stop_size(self, stop_size):
        """The client has sent a request to change the number of stop bits."""
        self.stop_size = stop_size

    def subnegotiate(self, subneg_data):
        """Action a request from the client to set one of various serial port
           parameters."""
        subcommand = subneg_data[0]
        data = subneg_data[1:]
        if subcommand == 1:
            baud_rate = struct.unpack_from('!L', data)[0]
            if baud_rate and baud_rate != self.baud_rate:
                self.set_baud_rate(baud_rate)
        elif subcommand == 2:
            data_size = data[0]
            if data_size and data_size != self.data_size:
                self.set_data_size(data_size)
        elif subcommand == 3:
            parity = data[0]
            if parity and parity != self.parity:
                self.set_parity(parity)
        elif subcommand == 4:
            stop_size = data[0]
            if stop_size and stop_size != self.stop_size:
                self.set_stop_size(stop_size)


class TelnetVMwareExtensionOption(TelnetOption):
    """The VMware Serial Port Proxy extension provides enhanced capabilities
       for emulated serial ports attached to virtual machines on VMware
       vSphere.  Its most noteworthy feature is to facilitate vMotion (live
       migration) of virtual machines with a serial port."""
    code = 0xe8
    name = 'VMWARE-TELNET-EXT'

    KNOWN_SUBOPTIONS_1 =  0
    KNOWN_SUBOPTIONS_2 =  1
    VMOTION_BEGIN      = 40
    VMOTION_GOAHEAD    = 41
    VMOTION_NOTNOW     = 43
    VMOTION_PEER       = 44
    VMOTION_PEER_OK    = 45
    VMOTION_COMPLETE   = 46
    VMOTION_ABORT      = 48
    VM_VC_UUID         = 80
    GET_VM_VC_UUID     = 81
    VM_NAME            = 82
    GET_VM_NAME        = 83
    DO_PROXY           = 70
    WILL_PROXY         = 71
    WONT_PROXY         = 73


class TelnetVMwareExtensionOptionServer(TelnetVMwareExtensionOption):
    """The server side of the VMware Serial Port Proxy extension is implemented
       by a virtual serial port concentrator."""
    # Maps sequence+secret to the TelnetVMwareExtensionOption for the
    # connection with that pending vMotion.
    active_vmotion_peers = {}

    class VMotionKey:
        def __init__(self, sequence, secret):
            self.sequence = sequence
            self.secret = secret
            self.key = bytes(sequence + secret)

    def __init__(self, service_uri):
        super().__init__()
        self.service_uri = service_uri
        self.vc_uuid = None
        self.vm_name = None
        self.uri_args = None # Query parameters appended to service_uri.
        self.will_proxy = None
        self.vmotion = None
        self.vmotion_peer = None

        # XXX: Need to abandon any incomplete vMotion when the connection is
        #      garbage-collected.

    def should_accept(self, them):
        return them

    def state_update(self, them, enabled):
        super().state_update(them, enabled)
        if enabled:
            self.send_subnegotiation(
                bytes([TelnetVMwareExtensionOption.KNOWN_SUBOPTIONS_2]),
                bytes([
                    TelnetVMwareExtensionOption.KNOWN_SUBOPTIONS_1,
                    TelnetVMwareExtensionOption.KNOWN_SUBOPTIONS_2,
                    TelnetVMwareExtensionOption.VMOTION_BEGIN,
                    TelnetVMwareExtensionOption.VMOTION_GOAHEAD,
                    TelnetVMwareExtensionOption.VMOTION_NOTNOW,
                    TelnetVMwareExtensionOption.VMOTION_PEER,
                    TelnetVMwareExtensionOption.VMOTION_PEER_OK,
                    TelnetVMwareExtensionOption.VMOTION_COMPLETE,
                    TelnetVMwareExtensionOption.VMOTION_ABORT,
                    TelnetVMwareExtensionOption.VM_VC_UUID,
                    TelnetVMwareExtensionOption.GET_VM_VC_UUID,
                    TelnetVMwareExtensionOption.VM_NAME,
                    TelnetVMwareExtensionOption.GET_VM_NAME,
                    TelnetVMwareExtensionOption.DO_PROXY,
                    TelnetVMwareExtensionOption.WILL_PROXY,
                    TelnetVMwareExtensionOption.WONT_PROXY]))

    @staticmethod
    def _sanitize_uuid(data):
        """Convert the given data into a UUID formatted as 32 hex
           characters."""
        try:
            uuid = data.decode(encoding='ascii').upper()
        except UnicodeError:
            return None

        uuid = ''.join(filter(lambda c: c in '0123456789ABCDEF', uuid))
        return uuid if len(uuid) == 32 else None

    def match_service_uri(self, service_uri):
        """Check whether the provided Service URI matches what we provide.  If
           any URI query args are present, parse them."""
        if service_uri == self.service_uri:
            return (True, None)
        if service_uri.startswith(self.service_uri + '?'):
            query_string = service_uri[len(self.service_uri) + 1:]
            return (True, urllib.parse.parse_qs(query_string,
                                                strict_parsing=True,
                                                keep_blank_values=True))
        return (False, None)

    def subnegotiate(self, subneg_data):
        """Actions required in response to VMware Serial Proxy messages:

        - In response to VC UUID, find the corresponding VM, and associate this
          telnet connection with it.
             * Handle when the VC UUID is not already known... create a new VM
               for it.
             * Handle when there is already a VM connection... it might be
               stale.
             * Handle when a vMotion is already in progress... it might have
               failed, but can not complete through this path, because the
               sequence and secret are required.
          Note that a VM can only have one active connection at a time.
          Associating a new connection to a VM will disassociate any prior
          connection.

        - In response to a VMOTION-BEGIN, generate the secret and store the
          (sequence, secret) pair in the VM's state.
             * Handle when there is already a (sequence, secret) pair...
               Indicates a prior vMotion did not complete and was not
               cancelled, so log this before replacing them.

        - In response to a VMOTION-PEER, look up the (sequence+secret) in the
          list of running vMotions, and map it back to a VM.
             * No further action, just report whether we found a VM.

        - In response to a VMOTION-ABORT from the existing connection, remove
          the sequence and secret from the VM's state.  (VMOTION-ABORT from the
          secondary connection must have no effect.)

        - In response to a VMOTION-COMPLETE from the secondary connection,
          remove the sequence and secret from the VM's state, eject the primary
          connection, make this the active connection for that VM.
          (VMOTION-COMPLETE from the primary connection must have no
          effect.)"""
        subcommand = subneg_data[0]
        subneg_data = subneg_data[1:]

        if subcommand == TelnetVMwareExtensionOption.KNOWN_SUBOPTIONS_1:
            pass # Ignore it.

        elif subcommand == TelnetVMwareExtensionOption.VM_VC_UUID and not self.vc_uuid:
            new_vc_uuid = self._sanitize_uuid(subneg_data)
            if new_vc_uuid:
                self.set_vc_uuid(new_vc_uuid)

        elif subcommand == TelnetVMwareExtensionOption.VM_NAME and not self.vm_name:
            try:
                new_vm_name = subneg_data.decode()
                self.set_vm_name(new_vm_name)
            except UnicodeError:
                pass

        elif subcommand == TelnetVMwareExtensionOption.DO_PROXY:
            self.uri_args = None
            direction = chr(subneg_data[0])
            service_uri = subneg_data[1:].decode()
            (uri_match, self.uri_args) = self.match_service_uri(service_uri)
            self.will_proxy = direction in ['C', 'S'] and uri_match

            if self.will_proxy:
                self.send_subnegotiation(
                    bytes([TelnetVMwareExtensionOption.WILL_PROXY])
                )
                self.send_subnegotiation(
                    bytes([TelnetVMwareExtensionOption.GET_VM_VC_UUID]))
                self.send_subnegotiation(
                    bytes([TelnetVMwareExtensionOption.GET_VM_NAME]))
            else:
                print('Warning: Proxy direction/serviceURI mismatch.')
                print(f'         Received "{direction}", "{service_uri}".')
                self.send_subnegotiation(
                    bytes([TelnetVMwareExtensionOption.WONT_PROXY])
                )

        elif subcommand == TelnetVMwareExtensionOption.VMOTION_BEGIN:
            if self.begin_vmotion(subneg_data):
                self.send_subnegotiation(
                    bytes([TelnetVMwareExtensionOption.VMOTION_GOAHEAD]),
                    self.vmotion.sequence,
                    self.vmotion.secret
                )
            else:
                self.send_subnegotiation(
                    bytes([TelnetVMwareExtensionOption.VMOTION_NOTNOW]),
                    subneg_data
                )

        elif subcommand == TelnetVMwareExtensionOption.VMOTION_PEER:
            # NOTE: The connection MUST be identified solely by the
            #       sequence+secret provided in this subnegotiation message.
            #       In theory, a VM might have multiple serial ports, and each
            #       would share the same VC UUID but would have distinct
            #       sequence+secret, and we must use the unique identifier to
            #       find the other port.
            self.vmotion_peer = self.find_vmotion_peer(subneg_data)
            if self.vmotion_peer:
                self.send_subnegotiation(
                    bytes([TelnetVMwareExtensionOption.VMOTION_PEER_OK]),
                    self.vmotion.sequence
                )
            # else:
            #   The protocol does not describe any error reply.  The source VM
            #   will time out.

        elif subcommand == TelnetVMwareExtensionOption.VMOTION_ABORT:
            self.abort_vmotion(subneg_data)

        elif subcommand == TelnetVMwareExtensionOption.VMOTION_COMPLETE:
            self.complete_vmotion(subneg_data)

        else:
            print('Warning: Unrecognized VMware-Serial-Proxy negotiation: %s' %
                  subneg_data.hex(' '))

    def service_uri_arg(self, arg_name):
        """If the named arg was given in the serviceUri string, fetch an array
           of the given values."""
        if not self.uri_args:
            return None
        try:
            return self.uri_args[arg_name]
        except KeyError:
            return None

    def set_vc_uuid(self, vc_uuid):
        """The other party has informed us of the VC UUID for this
           connection."""
        self.vc_uuid = vc_uuid

    def set_vm_name(self, vm_name):
        """The other party has informed us of the name of this VM."""
        self.vm_name = vm_name

    # ============ vMotion Handling =============

    def begin_vmotion(self, data):
        """Start preparing a vMotion "source" by generating a secret and
           placing the sequence and secret into the list of active vMotions."""
        if self.vmotion:
            # vMotion source should have sent VMOTION-ABORT but did not.  Oh
            # well.
            print('Warning: A prior vMotion did not complete.  Replacing it.')
            self.abandon_vmotion()

        self.vmotion = \
            TelnetVMwareExtensionOptionServer.VMotionKey(data, secrets.token_bytes(8))
        self.active_vmotion_peers[self.vmotion.key] = self
        return True

    def find_vmotion_peer(self, data):
        """Start the process of connecting a vMotion "destination" VM by
           looking up the connection using the provided sequence and secret."""
        key = bytes(data)
        try:
            peer = self.active_vmotion_peers[key]
        except KeyError:
            print('Warning: vMotion peer not found.')
            return None

        self.vmotion = peer.vmotion
        return peer

    def _end_vmotion(self):
        """Terminate any active vMotion on this connection.  It has either
           completed successfully or failed entirely."""
        if self.vmotion:
            try:
                del self.active_vmotion_peers[self.vmotion.key]
            except KeyError:
                pass

        self.vmotion = None
        self.vmotion_peer = None

    def switch_port_to_new_peer(self, other_vo):
        """Put a vMotion transfer into effect by connecting *this* option
           instance to the port currently owned by other_vo."""

    def complete_vmotion(self, unused_data):
        """Handle a request from a vMotion destination to complete the
           transfer."""
        if self.vmotion_peer:
            self.switch_port_to_new_peer(self.vmotion_peer)
        self._end_vmotion()

    def abort_vmotion(self, unused_data):
        """Handle a request from a vMotion source to abort the transfer."""
        self._end_vmotion()

    def abandon_vmotion(self):
        """A vMotion did not complete and was not explicitly abandoned, but was
           otherwise determined to no longer be valid and should be
           discarded now."""
        self._end_vmotion()


class TelnetVMwareExtensionOptionClient(TelnetVMwareExtensionOption):
    """The client side of the VMware Serial Port Proxy extension is implemented
       by a virtual serial port, such as may be configured in a virtual machine
       running on VMware ESXi.  A stub client is implemented here to facilitate
       testing."""

    def should_accept(self, them):
        return not them

    def state_update(self, them, enabled):
        super().state_update(them, enabled)
        if enabled:
            self.send_subnegotiation(
                bytes([TelnetVMwareExtensionOption.KNOWN_SUBOPTIONS_1]),
                bytes([
                    TelnetVMwareExtensionOption.KNOWN_SUBOPTIONS_1,
                    TelnetVMwareExtensionOption.KNOWN_SUBOPTIONS_2,
                    TelnetVMwareExtensionOption.VMOTION_BEGIN,
                    TelnetVMwareExtensionOption.VMOTION_GOAHEAD,
                    TelnetVMwareExtensionOption.VMOTION_NOTNOW,
                    TelnetVMwareExtensionOption.VMOTION_PEER,
                    TelnetVMwareExtensionOption.VMOTION_PEER_OK,
                    TelnetVMwareExtensionOption.VMOTION_COMPLETE,
                    TelnetVMwareExtensionOption.VMOTION_ABORT,
                    TelnetVMwareExtensionOption.VM_VC_UUID,
                    TelnetVMwareExtensionOption.GET_VM_VC_UUID,
                    TelnetVMwareExtensionOption.VM_NAME,
                    TelnetVMwareExtensionOption.GET_VM_NAME,
                    TelnetVMwareExtensionOption.DO_PROXY,
                    TelnetVMwareExtensionOption.WILL_PROXY,
                    TelnetVMwareExtensionOption.WONT_PROXY]))
