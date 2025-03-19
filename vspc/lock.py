# The client can request one of five locking modes when connecting to a serial
# port:
#
# READWRITE: Successful connection requries that no other clients have
#               exclusive access to this port.
#            This connection will be read-write.
#            While connected, no other clients will be granted exclusive write
#               access to this port.
#
# READONLY: Successful connection requires that no other clients have exclusive
#              access to this port.
#           This connection will be read-only.
#           While connected, no other clients will be granted exclusive access to
#              this port.
#
# EXCLUSIVE: Successful connection requires that no other clients are connected
#               to this port.
#            This connection will be read-write.
#            While connected, no other clients may connect to this port.
#
# EXCL_WRITE: Successful connection requires that no other clients have write
#               access to this port.  Other read-only connections are OK.
#             This connection will be read-write.
#             While connected, no other clients will be granted write access to
#                this port.
#
# READONLY_OK: Successful connection requires that no other clients have
#                 exclusive access to this port.
#              If there are any other exclusive write clients, this connection
#                 will be read-only.  Otherwise, it will be read-write.
#              While connected, no other clients will be granted exclusive
#                 access which conflicts with this port's access (i.e. no
#                 exclusive access if this connection is read-only, and no
#                 exclusive-write access if this connection is read-write.)
#
# The default is READWRITE.  When all clients use READWRITE, there are no restrictions
# on simultaneous connections to a serial port.

READWRITE   = 0x00
READONLY    = 0x01
EXCLUSIVE   = 0x10
EXCL_WRITE  = 0x11
READONLY_OK = 0x20
