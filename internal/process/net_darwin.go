package process

/*
#cgo LDFLAGS: -lproc

#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

// Defined in process_darwin.c
int find_pid_by_ip(uint16_t src_port, uint16_t dst_port, struct in_addr src_ip, struct in_addr dst_ip, pid_t *out_pid);
*/
import "C"

import (
	"fmt"
	"net"
	"unsafe"
)

func findPIDByIP(srcPort, dstPort uint16, srcAddr, dstAddr net.IP) (PID, error) {
	if srcPort == 0 {
		return 0, ErrNotFound
	}

	ip4Src := srcAddr.To4()
	ip4Dst := dstAddr.To4()
	if ip4Src == nil || ip4Dst == nil {
		return 0, fmt.Errorf("only IPv4 addresses are supported")
	}

	var cSrcIP C.struct_in_addr
	var cDstIP C.struct_in_addr

	copy((*[4]byte)(unsafe.Pointer(&cSrcIP.s_addr))[:], ip4Src)
	copy((*[4]byte)(unsafe.Pointer(&cDstIP.s_addr))[:], ip4Dst)

	var pid C.pid_t

	ret := C.find_pid_by_ip(
		C.uint16_t(srcPort),
		C.uint16_t(dstPort),
		cSrcIP,
		cDstIP,
		&pid,
	)

	switch {
	case ret == 1:
		return 0, ErrNotFound
	case ret < 0:
		return 0, fmt.Errorf("find pid for ip/port connection: %s", C.GoString(C.strerror(-ret)))
	}

	return PID(pid), nil
}
