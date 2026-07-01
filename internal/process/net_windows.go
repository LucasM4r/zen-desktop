package process

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func findPIDByIP(srcPort, dstPort uint16, srcIP, dstIP net.IP) (PID, error) {
	tcpTable, err := getTCPTable()
	if err != nil {
		return 0, fmt.Errorf("get tcp table: %v", err)
	}

	// Pre-convert to network byte order.
	netSrcPort := uint32(srcPort<<8 | srcPort>>8)
	netDstPort := uint32(dstPort<<8 | dstPort>>8)

	ip4Src := srcIP.To4()
	ip4Dst := dstIP.To4()
	if ip4Src == nil || ip4Dst == nil {
		return 0, fmt.Errorf("invalid IPv4 addresses: src=%v, dst=%v", srcIP, dstIP)
	}

	winSrcIP := binary.NativeEndian.Uint32(ip4Src)
	winDstIP := binary.NativeEndian.Uint32(ip4Dst)

	for _, r := range tcpTable {

		if (r.dwLocalPort&0xFFFF) == netSrcPort &&
			(r.dwRemotePort&0xFFFF) == netDstPort &&
			r.dwLocalAddr == winSrcIP &&
			r.dwRemoteAddr == winDstIP {
			return PID(r.dwOwningPid), nil
		}
	}

	return 0, ErrNotFound
}
func getTCPTable() ([]mibTcpRowOwnerPid, error) {
	var bufSize uint32
	ret := getExtendedTcpTable(nil, &bufSize, false, windows.AF_INET, tcpTableOwnerPidAll, 0)
	if ret != uint32(windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, fmt.Errorf("GetExtendedTcpTable size query: %w", syscall.Errno(ret))
	}

	for {
		table := make([]byte, bufSize)
		ret = getExtendedTcpTable(&table[0], &bufSize, false, windows.AF_INET, tcpTableOwnerPidAll, 0)
		switch ret {
		case 0:
			dwNumEntries := int(*(*uint32)(unsafe.Pointer(&table[0])))
			return unsafe.Slice((*mibTcpRowOwnerPid)(unsafe.Pointer(&table[mibTcpTableOwnerPidTableOffset])), dwNumEntries), nil
		case uint32(windows.ERROR_INSUFFICIENT_BUFFER):
			continue
		default:
			return nil, fmt.Errorf("GetExtendedTcpTable: %w", syscall.Errno(ret))
		}
	}
}
