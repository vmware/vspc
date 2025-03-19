"""A virtual serial port concentrator (vSPC) suitable for VMware ESXi virtual
   machines.  Facilitates the VMware vMotion migration of virtual machines with
   network-attached serial ports, ensuring that no data loss occurs.

   Features:
     - Supports up to 16,000 concurrent virtual machines and 50 vMotion
       events per second.
     - Configurable backends support logging to disk, logging to a memory
       buffer, logging to Telnet connection(s),

   VmPorts[port_id]:
      - port_id
      - config
      - client_telnet_sockets[]
      - backends[]
      - veo (VspcTelnetVMwareExtensionOption) -> conn -> TelnetConnection.

    VmPortConfig:
      - port_id (or partial port_id, and/or wildcards, or "default")
      - port_backend_config[]
          - backend and configuration
      - requested listen port
      - readonly
"""
import os
import sys
import asyncio
import time
import datetime
import telnet.protocol
import telnet.connection
import vspc.backend
import vspc.lock
import vspc.admin_option

total_serial_data_received = 0
total_serial_data_transmitted = 0
admin_connections_received = 0
admin_connections_active = 0
vm_connections_received = 0
vm_connections_active = 0
vmotion_begins = 0
vmotion_peers = 0
vmotion_completes = 0
vmotion_aborts = 0
vmotion_abandons = 0
start_time = datetime.datetime.now()

class PortAccessDenied(Exception):
    pass

class PortNotFound(Exception):
    pass

class VspcVmPort:
    vm_ports = {}

    def __init__(self, veo, vc_uuid, port_label, vm_name):
        # veo is the VspcTelnetVMwareExtensionOption which is attached to the
        # VM's current serial port connection.  vMotion changes it.
        self.veo = veo

        self.vc_uuid = vc_uuid
        self.port_label = port_label
        self.vm_name = vm_name
        self.listening_uri = None

        self.backends = [vspc.backend.VMPortBackendDisk(self)]
        self.readonly_backends = []
        self.readwrite_backends = []
        self.exclusive_backend = None
        self.exclusive_write_backend = None

    def __str__(self):
        """Produce a string representation of this VM Port's identity."""
        pl = f', port label="{self.port_label}"' if self.port_label else ''
        return f'<VM Port: UUID={self.vc_uuid}{pl}, name="{self.vm_name}">'

    @staticmethod
    def make_port_id(vc_uuid, port_label):
        """Format a VM Port identifier into the form used for display and for
           lookup."""
        return '.'.join((vc_uuid, port_label)) if port_label else vc_uuid

    @staticmethod
    def port_for(veo, vc_uuid, port_label, vm_name):
        """Look up a VM Port with the given information.  If one does not
           already exist, it is created."""
        port_id = VspcVmPort.make_port_id(vc_uuid, port_label)
        try:
            return VspcVmPort.vm_ports[port_id]
        except KeyError:
            pass
        new_port = VspcVmPort(veo, vc_uuid, port_label, vm_name)
        VspcVmPort.vm_ports[port_id] = new_port
        print('New: %s' % new_port)
        return new_port

    @staticmethod
    def port_list():
        """Produce a list of all of the VM Ports known to this vSPC."""
        return ((k, v.vm_name, v.listening_uri) \
            for (k, v) in VspcVmPort.vm_ports.items())

    def switch_to_veo(self, new_veo):
        """Hand off this VM Port from one VM connection ('self.veo') to a new
           VM connection ('new_veo').  This is only used during vMotion, and is
           the critical step where the VM's connection changes from the source
           host to the destination host."""
        self.veo = new_veo

    def determine_port_access(self, requested_access):
        """Given the access mode requested by a new backend desiring to
           connect to this port, figure out whether the access will be granted,
           based upon the set of existing backend connections.  Returns True if
           read-write access is granted, False if read-only access is granted,
           or raises a PortAccessDenied exception if no access is possible."""
        write_ok = requested_access != vspc.lock.READONLY

        if self.exclusive_backend:
            raise PortAccessDenied("Another client has exclusive access to this port.")

        if self.exclusive_write_backend:
            if requested_access == vspc.lock.READONLY_OK:
                # Downgrade to read-only.
                write_ok = False
            elif requested_access != vspc.lock.READWRITE:
                raise PortAccessDenied("Another client has exclusive write access to this port.")

        if requested_access == vspc.lock.EXCLUSIVE:
            # There must be no other backends.
            if self.readonly_backends or self.readwrite_backends:
                raise PortAccessDenied("Exclusive access was requested but another client has access to this port.")

        elif requested_access == vspc.lock.EXCL_WRITE:
            # There must be no other writer.
            if self.readwrite_backends:
                raise PortAccessDenied("Exclusive write access was requested but another client has write access to this port.")

        return write_ok

    def add_backend(self, b, requested_access, write):
        """Add the backend 'b' to the list of backends which will receive
           communication from this VM Port -- and which (optionally) can send
           data to this VM Port."""

        self.backends.append(b)

        if requested_access == vspc.lock.EXCLUSIVE:
            self.exclusive_backend = b
        elif requested_access == vspc.lock.EXCL_WRITE:
            self.exclusive_write_backend = b
        elif write:
            self.readwrite_backends.append(b)
        else:
            self.readonly_backends.append(b)

    def remove_backend(self, b):
        """Remove the backend 'b' from the list of backends for this VM
           Port.  The backend will no longer receive communication from this VM
           Port."""

        self.backends.remove(b)

        if self.exclusive_backend == b:
            self.exclusive_backend = None
        elif self.exclusive_write_backend == b:
            self.exclusive_write_backend = None
        else:
            try:
                self.readwrite_backends.remove(b)
            except ValueError:
                self.readonly_backends.remove(b)

    def receive_bytes(self, veo, b):
        """The VM has produced bytes of data from its serial port.  Send them
           to each registered backend."""
        if veo != self.veo:
            print(f'veo={veo!r}({veo!s}) self.veo={self.veo!r}({self.veo!s})')
            raise telnet.protocol.TelnetProtocolError('Received data from an unexpected source.')
        for backend in self.backends:
            backend.receive_bytes(b)

    def send_bytes(self, b):
        """A backend has produced bytes to data to send to the VM's serial
           port.  Send them to the VM"""
        self.veo.send_bytes(b)


# ------------------- Virtual Machine Serial Port Connections --------------

class VspcTelnetVMwareExtensionOption(telnet.option.TelnetVMwareExtensionOptionServer):
    def __init__(self):
        super().__init__('vSPC.py')
        self.port = None

    def get_port_label(self):
        label_list = None
        try:
            if self.uri_args:
                label_list = self.uri_args['port']
        except KeyError:
            return None

        return label_list[0] if label_list else None

    def check_identity(self):
        # XXX Do we need a notification when will_proxy is updated?
        if self.port:
            # Already associated with a port.
            return

        if not self.vm_name or not self.vc_uuid or not self.will_proxy:
            # Insufficient information to set up a port.
            return

        port_label = self.get_port_label()
        self.port = VspcVmPort.port_for(self, self.vc_uuid, port_label,
                                        self.vm_name)

    def set_vc_uuid(self, vc_uuid):
        super().set_vc_uuid(vc_uuid)
        if self.port and self.port.vc_uuid != self.vc_uuid:
            raise telnet.protocol.TelnetProtocolError(
                'Tried to change VC UUID for in-use port.')
        self.check_identity()

    def set_vm_name(self, vm_name):
        super().set_vm_name(vm_name)
        self.check_identity()

    def switch_port_to_new_peer(self, other_veo):
        """This VO is the destination of a valid vMotion request which is now
        being completed, so the transfer must go into effect.  Its peer (the
        source) is other_veo.  To put the vMotion into effect, the port from
        other_veo should be claimed and put into use for this VO."""
        if not other_veo.port:
            raise telnet.protocol.TelnetProtocolError(
                'Tried to complete vMotion when the source is not ready.')
        if self.vc_uuid and self.vc_uuid != other_veo.vc_uuid:
            raise telnet.protocol.TelnetProtocolError(
                'Tried to complete a vMotion on an already-connected port.')
        if other_veo.vc_uuid and not self.vc_uuid:
            self.vc_uuid = other_veo.vc_uuid
        if other_veo.vm_name and not self.vm_name:
            self.vm_name = other_veo.vm_name

        # Claim the port now.
        self.port = other_veo.port
        self.port.switch_to_veo(self)

    def disconnect_from_vm_port(self):
        if self.port and self.port.veo == self:
            self.port.switch_to_veo(None)

    def del_port(self):
        if self.port and self.port.veo == self:
            vm_port_id = self.port.make_port_id(self.port.vc_uuid, self.port.port_label)
            del VspcVmPort.vm_ports[vm_port_id];

    def receive_bytes(self, b):
        global total_serial_data_received

        total_serial_data_received += len(b)

        if not self.port:
            raise telnet.protocol.TelnetProtocolError(
                'Received data before adequate identification received.')
        if not self.port.veo: # XXX: Ewwwwwww.
            self.port.switch_to_veo(self)
        self.port.receive_bytes(self, b)

    def send_bytes(self, b):
        global total_serial_data_transmitted

        total_serial_data_transmitted += len(b)
        self.conn.send_bytes(b)

    # ------------------- vMotion hooks ------------

    # The superclass handles all the vMotion logic.  We just collect stats.

    def begin_vmotion(self, data):
        global vmotion_begins
        vmotion_begins += 1
        return super().begin_vmotion(data)

    def find_vmotion_peer(self, data):
        global vmotion_peers
        vmotion_peers += 1
        return super().find_vmotion_peer(data)

    def complete_vmotion(self, data):
        global vmotion_completes
        vmotion_completes += 1
        super().complete_vmotion(data)

    def abort_vmotion(self, data):
        global vmotion_aborts
        vmotion_aborts += 1
        print(f'{self.port}: vMotion abort.')
        super().abort_vmotion(data)

    def abandon_vmotion(self):
        global vmotion_abandons
        vmotion_abandons += 1
        print(f'{self.port}: vMotion abandoned.')
        super().abandon_vmotion()


async def vm_port_accept(reader, writer):
    global vm_connections_received, vm_connections_active

    vm_connections_received += 1
    vm_connections_active += 1
    try:
        t = telnet.connection.TelnetConnection(reader, writer, debug=True)
        veo = VspcTelnetVMwareExtensionOption()
        t.add_option(veo)
        async for o in t.telnet_stream():
            if isinstance(o, bytes):
                veo.receive_bytes(o)

    except EOFError:
        pass
    finally:
        vm_connections_active -= 1
        veo.del_port()
        veo.disconnect_from_vm_port()
        writer.close()
    try:
        await writer.drain()
        await writer.wait_closed()
    except ConnectionResetError:
        pass
    except BrokenPipeError:
        pass

async def vm_port_task():
    vm_port_server = await asyncio.start_server(
        vm_port_accept, '0.0.0.0', 13370)

    addrs = ', '.join(str(sock.getsockname()) for sock in vm_port_server.sockets)
    print(f'vSPC serving on {addrs}.')

    async with vm_port_server:
        await vm_port_server.serve_forever()

# --------------------- Administrative Client connnections ----------------

class VspcAdminClientBackend(vspc.backend.VMPortBackend):
    """A vSPC client connected to a port needs to register with that port as a
       backend so that it is notified of incoming data.  Class
       VspcAdminClientBackend acts as that backend and forwards the data to the
       VspcAdminOptionServerImpl."""
    def __init__(self, vm_port, client_vao):
        super().__init__(vm_port)
        self.client_vao = client_vao

    def receive_bytes(self, b):
        """Serial data from the VM has arrived.  Forward it to this vSPC admin
           client."""
        self.client_vao.receive_bytes(b)


class VspcAdminOptionServerImpl(vspc.admin_option.VspcAdminOptionServer):
    """Class VspcAdminOptionServerImpl provides the glue to connect the generic
       implementation of the server-side of the vSPC admin telnet option to the
       vSPC server implementation."""
    def __init__(self):
        super().__init__()
        self.port = None
        self.port_backend = None

    def vm_port_list(self):
        """The vSPC admin client requested a list of the VM ports we know
           about."""
        return VspcVmPort.port_list()

    def disconnect_from_vm_port(self):
        """Ensure that this vSPC admin client is no longer connected to any VM
           port."""
        if self.port:
            # Disconnect from any existing port.
            self.port.remove_backend(self.port_backend)
            self.port_backend = None
            self.port = None

    def connect_to_vm_port(self, vm_port_id, requested_access):
        """The vSPC admin client requested that we connect to the given VM
           port.  Returns True upon success."""
        self.disconnect_from_vm_port()

        try:
            port = VspcVmPort.vm_ports[vm_port_id]
        except KeyError as e:
            # Not a port we know about.
            # XXX: Clear up exception handling here.  Propagate a message to
            #      the client.
            #raise PortNotFound(vm_port_id) from e
            return False

        try:
            # Figure out what access we will have to the port.  Raises a
            # PortAccessDenied exception if no access can be granted.
            write_ok = port.determine_port_access(requested_access)

            # Wrap ourselves in a backend and register it with the VM port so
            # that we find out about data arriving from that VM port.
            #
            # Also keep a reference to the VM port so that we can send data
            # back the other way.
            self.port = port
            self.port_backend = VspcAdminClientBackend(port, self)
            port.add_backend(self.port_backend, requested_access, write_ok)
        except PortAccessDenied as e:
            # XXX: Clear up exception handling here.  Propagate a message to
            #      the client.
            return False

    def receive_bytes(self, b):
        """Serial data from the VM has arrived.  Forward it to this vSPC admin
           client."""
        self.conn.send_bytes(b)

    def send_bytes(self, b):
        """Serial data from the vSPC admin client has arrived.  Forward it to
           the VM port."""
        if self.port:
            self.port.send_bytes(b)


async def admin_accept(reader, writer):
    global admin_connections_received, admin_connections_active

    admin_connections_received += 1
    admin_connections_active += 1
    try:
        t = telnet.connection.TelnetConnection(reader, writer, debug=True)
        vao = VspcAdminOptionServerImpl()
        t.add_option(vao)
        async for o in t.telnet_stream():
            if isinstance(o, bytes):
                # An admin client sent data for our connection.
                print(f'admin: {o!r}')
                vao.send_bytes(o)

    except EOFError:
        pass
    finally:
        admin_connections_active -= 1
        vao.disconnect_from_vm_port()
        writer.close()
    try:
        await writer.drain()
        await writer.wait_closed()
    except ConnectionResetError:
        pass
    except BrokenPipeError:
        pass

async def admin_task():
    admin_server = await asyncio.start_server(
        admin_accept, '127.0.0.1', 13371)

    addrs = ', '.join(str(sock.getsockname()) for sock in admin_server.sockets)
    print(f'vSPC admin console serving on {addrs}.')

    async with admin_server:
        await admin_server.serve_forever()

# --------------------- Runtime Statistics -----------------

def print_stats():
    now = datetime.datetime.now()
    times = os.times()
    loadavg = os.getloadavg()
    print("%s: Time: clock:%0.6f sec, CPU:%0.6f sec, sys:%0.2f sec, user:%0.2f sec, loadavg:%0.2f %0.2f %0.2f." % (
        now,
        (now - start_time).total_seconds(), time.clock_gettime(time.CLOCK_PROCESS_CPUTIME_ID),
        times.system, times.user,
        loadavg[0], loadavg[1], loadavg[2]))
    print('%s: vMotion activity: BEGINs:%u, PEERs:%a, COMPLETEs:%u, ABORTs:%u, abandons:%u, in-progress:%u.' % (
        now, vmotion_begins, vmotion_peers, vmotion_completes, vmotion_aborts,
        vmotion_abandons,
        len(telnet.option.TelnetVMwareExtensionOptionServer.active_vmotion_peers)))
    print("%s: Total inbound connections accepted: VM serial port:%u, admin:%u" % (
        now,
        vm_connections_received,
        admin_connections_received))
    print('%s: Current connections: VM serial port:%u, admin:%u' % (
        now,
        vm_connections_active,
        admin_connections_active))
    print("%s: Serial data: received from VMs:%u bytes, transmitted to VMs:%u bytes" % (
        now,
        total_serial_data_received, total_serial_data_transmitted))
    sys.stdout.flush()

async def stats_task():
    STATS_INTERVAL_SEC = 60
    while True:
        await asyncio.sleep(STATS_INTERVAL_SEC)
        print_stats()

# ----------------- vSPC Server -----------------------------

async def vspc_main():
    asyncio.create_task(stats_task())
    asyncio.create_task(admin_task())
    await asyncio.create_task(vm_port_task())


# We use a lot of FDs.  Increase the open-file limit for the process.

try:
    import resource
    file_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    print('Initial FD limits: soft %u, hard %u.' % file_limit)
    new_file_limit = (max(file_limit[0], 32767), max(file_limit[1], 32767))
    if new_file_limit != file_limit:
        resource.setrlimit(resource.RLIMIT_NOFILE, new_file_limit)
        print('Current FD limits: soft %u, hard %u.' % resource.getrlimit(resource.RLIMIT_NOFILE))
except ImportError:
    pass
except ValueError:
    print('Failed to adjust resource limits.')

# Increase the process priority.  The vSPC is on the vMotion critical path, so
# it is critical that we are not impeded by any lower-priority work.

orig_proc_priority = os.getpriority(os.PRIO_PROCESS, 0)
try:
    os.setpriority(os.PRIO_PROCESS, 0, -20)
    new_proc_priority = os.getpriority(os.PRIO_PROCESS, 0)
    if new_proc_priority == orig_proc_priority:
        print(f'Process priority was {orig_proc_priority} and was not changed.')
    else:
        print(f'Process priority changed from {orig_proc_priority} to {new_proc_priority}.')
except PermissionError:
    print(f'Failed to raise process priority from {orig_proc_priority}.')

try:
    asyncio.run(vspc_main(), debug=False)
finally:
    print_stats()
