package process

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"syscall"

	"golang.org/x/sys/unix"
)

// inetDiagSockID represents the inet_diag_sockid structure used in netlink requests.
type inetDiagSockID struct {
	IDiagSrcPort   [2]byte
	IDiagDstPort   [2]byte
	IDiagSrc       [16]byte
	IDiagDst       [16]byte
	IDiagInterface uint32
	IDiagCookie    [2]uint32
}

// inetDiagReqV2 represents the inet_diag_req_v2 structure used in netlink requests.
type inetDiagReqV2 struct {
	SDiagFamily   uint8
	SDiagProtocol uint8
	IDiagExt      uint8
	Pad           uint8
	IDiagStates   uint32
	ID            inetDiagSockID
}

// findPIDByIP finds the PID of the process that owns the TCP connection specified by the source and destination IP addresses and ports.
func findPIDByIP(srcPort, dstPort uint16, srcAddr, dstAddr net.IP) (PID, error) {
	inode, err := findInode(srcPort, dstPort, srcAddr, dstAddr)
	if err != nil {
		return 0, fmt.Errorf("find inode by netlink: %w", err)
	}

	pid, err := findPID(inode)
	if err != nil {
		return 0, fmt.Errorf("find pid: %w", err)
	}

	return pid, nil
}

// findInode finds the inode number of the socket associated with the given source and destination IP addresses and ports using netlink.
func findInode(srcPort, dstPort uint16, srcAddr, dstAddr net.IP) (uint64, error) {

	// Create a netlink socket to communicate with the kernel
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return 0, fmt.Errorf("create netlink socket: %v", err)
	}
	defer unix.Close(fd)

	req := inetDiagReqV2{
		SDiagFamily:   unix.AF_INET,
		SDiagProtocol: unix.IPPROTO_TCP,
		IDiagStates:   0xffffffff,
	}

	// Fill in the source and destination ports and IP addresses in the request
	binary.BigEndian.PutUint16(req.ID.IDiagSrcPort[:], srcPort)
	binary.BigEndian.PutUint16(req.ID.IDiagDstPort[:], dstPort)

	ip4Src := srcAddr.To4()
	ip4Dst := dstAddr.To4()
	if ip4Src == nil || ip4Dst == nil {
		return 0, fmt.Errorf("only IPv4 addresses are supported")
	}
	copy(req.ID.IDiagSrc[:], ip4Src)
	copy(req.ID.IDiagDst[:], ip4Dst)

	// Set the cookie to all ones to match any socket
	req.ID.IDiagCookie = [2]uint32{0xffffffff, 0xffffffff}

	// Prepare the netlink message header
	nlhmsghdr := unix.NlMsghdr{
		Len:   uint32(unix.SizeofNlMsghdr + binary.Size(req)),
		Type:  unix.SOCK_DIAG_BY_FAMILY,
		Flags: unix.NLM_F_REQUEST,
		Seq:   1,
	}

	// Serialize the netlink message header and request into a buffer
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.NativeEndian, nlhmsghdr); err != nil {
		return 0, fmt.Errorf("write netlink header: %v", err)
	}
	if err := binary.Write(buf, binary.NativeEndian, req); err != nil {
		return 0, fmt.Errorf("write netlink request: %v", err)
	}

	// Send the netlink request to the kernel
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Sendto(fd, buf.Bytes(), 0, sa); err != nil {
		return 0, fmt.Errorf("send netlink request: %v", err)
	}

	// Receive the response from the kernel
	resBuf := make([]byte, 16384)
	n, _, err := unix.Recvfrom(fd, resBuf, 0)
	if err != nil {
		return 0, fmt.Errorf("receive netlink response: %v", err)
	}

	// Parse the netlink messages from the response buffer
	messages, err := syscall.ParseNetlinkMessage(resBuf[:n])
	if err != nil {
		return 0, fmt.Errorf("parse netlink message: %v", err)
	}

	// Iterate through the netlink messages to find the inode of the socket
	for _, msg := range messages {
		if msg.Header.Type == unix.NLMSG_DONE {
			break
		}

		// Check for errors in the netlink message
		if msg.Header.Type == unix.NLMSG_ERROR {
			if len(msg.Data) >= 4 {
				errno := int32(binary.NativeEndian.Uint32(msg.Data[:4]))
				if errno != 0 {
					return 0, fmt.Errorf("netlink kernel error: %v", unix.Errno(-errno))
				}
			}
			return 0, fmt.Errorf("netlink error: unknown error missing data")
		}

		// Check if the message is of type SOCK_DIAG_BY_FAMILY and extract the inode from the message data
		if msg.Header.Type == unix.SOCK_DIAG_BY_FAMILY {
			if len(msg.Data) < 72 {
				continue
			}

			inode := binary.NativeEndian.Uint32(msg.Data[68:72])
			if inode != 0 {
				return uint64(inode), nil
			}
		}
	}

	return 0, fmt.Errorf("no inode found for the given socket parameters")
}

// findPID finds the PID of the process that owns the socket with the given inode by scanning the /proc filesystem.
func findPID(inode uint64) (PID, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}

	target := fmt.Sprintf("socket:[%d]", inode)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue // Not a PID directory.
		}

		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // Permission denied or process gone.
		}

		for _, fd := range fds {
			if fd.Type() != fs.ModeSymlink {
				continue
			}

			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if link == target {
				return PID(pid), nil
			}
		}
	}
	return 0, ErrNotFound
}
