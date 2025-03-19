import os
#import termios
#import telnet.protocol
#import telnet.option

class VMPortBackend:
    """A VMPortBackend represents a serial port output.  It might be to a
    buffer in memory, or to a file on disk, or to a TCP socket, or any manner
    of thing."""

    def __init__(self, vm_port):
        self.vm_port = vm_port

    def __str__(self):
        return '%s (%s)' % (self.vm_port.vm_name, self.vm_port.vc_uuid)

    def receive_bytes(self, b):
        raise NotImplementedError()


class VMPortBackendTcpListen(VMPortBackend):
    def __init__(self, vm_port, tcp_port=None):
        super().__init__(vm_port)


class VMPortBackendTcpConnect(VMPortBackend):
    def __init__(self, vm_port, tcp_port=None):
        super().__init__(vm_port)


class VMPortBackendDisk(VMPortBackend):
    """A VMPortBackendDisk logs serial data to a file named for the VC UUID of
    the associated VM."""
    def __init__(self, vm_port):
        super().__init__(vm_port)
        filename = self.generate_filename()
        self.file = open(filename, 'ab+')

    def generate_filename(self):
        dir_name = os.path.join('var/run/vspc', self.vm_port.vc_uuid[0:2], self.vm_port.vc_uuid[0:4])
        os.makedirs(dir_name, exist_ok=True)
        return os.path.join(dir_name, '%s.log' % self.vm_port.vc_uuid)

    def receive_bytes(self, b):
        self.file.write(b)


class VMPortBackendPhysicalSerialPort(VMPortBackend):
    """A VMPortBackendPhysicalSerialPort connects to a physical serial port on
    the vSPC host."""
    # XXX: Use TelnetComPortOption here, and set the physical port to match the
    #      VM's baud/parity/start/stop configuration.
    def __init__(self, vm_port):
        raise NotImplementedError()


class VMPortBackendMemory(VMPortBackend):
    """A VMPortBackendMemory stashes serial data into a buffer in memory."""
    def __init__(self, vm_port):
        super().__init__(vm_port)
        self.buf = bytearray(0)

    def receive_bytes(self, b):
        self.buf += b


class VMPortBackendNullModem(VMPortBackend):
    """A VMPortBackendNullModem connects directly between two VMs identified by
    their UUIDs."""
    def __init__(self, vm_port):
        super().__init__(vm_port)
        self.other_port = None

    def set_other(self, other_port):
        self.other_port = other_port

    def receive_bytes(self, b):
        raise NotImplementedError() # until we have a way to reach set_other...
        #if self.other_port:
        #    self.other_port.vm_port.conn.telnet.send_data(b)
