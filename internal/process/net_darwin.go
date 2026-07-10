package process

/*
#cgo LDFLAGS: -lproc

#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

// Defined in process_darwin.c
int find_pid_by_port(uint16_t port, pid_t *out_pid);
*/
import "C"

import (
	"fmt"
	"net"
)

func findPIDByIP(srcPort, dstPort uint16, srcIP, dstIP net.IP) (PID, error) {
	if srcPort == 0 {
		return 0, ErrNotFound
	}

	var pid C.pid_t

	ret := C.find_pid_by_port(C.uint16_t(srcPort), &pid)

	switch {
	case ret == 1:
		return 0, ErrNotFound
	case ret < 0:
		return 0, fmt.Errorf("find pid for ip/port connection: %s", C.GoString(C.strerror(-ret)))
	}

	return PID(pid), nil
}
