//go:build windows
// +build windows

// Copyright 2026 workturnedplay
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dnsbollocks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	//"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	AF_INET             = 2
	UDP_TABLE_OWNER_PID = 1 // MIB_UDPTABLE_OWNER_PID
)

var (
	modiphlpapi              = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedUdpTable  = modiphlpapi.NewProc("GetExtendedUdpTable")
	modkernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procQueryFullProcessName = modkernel32.NewProc("QueryFullProcessImageNameW")

	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = kernel32.NewProc("Process32FirstW")
	procProcess32Next            = kernel32.NewProc("Process32NextW")
)

// pidAndExeForUDP returns (pid, exePath, error).
// clientAddr should be the remote UDP address observed on the server side (e.g., 127.0.0.1:49936).
func PidAndExeForUDP(clientAddr *net.UDPAddr) (uint32, string, error) {
	//capital P in PidAndExeForUDP means exported, apparently!
	if clientAddr == nil {
		return 0, "", errors.New("nil clientAddr")
	}
	ip4 := clientAddr.IP.To4()
	if ip4 == nil {
		return 0, "", errors.New("only IPv4 supported")
	}
	port := uint16(clientAddr.Port)

	// First call to GetExtendedUdpTable to get required buffer size.
	var bufSize uint32
	ret, _, _ := procGetExtendedUdpTable.Call(
		0,
		uintptr(unsafe.Pointer(&bufSize)),
		0,
		uintptr(AF_INET),
		uintptr(UDP_TABLE_OWNER_PID),
		0,
	)
	if ret != uintptr(syscall.ERROR_INSUFFICIENT_BUFFER) && ret != 0 {
		return 0, "", fmt.Errorf("GetExtendedUdpTable size query failed: %d", ret)
	}
	if bufSize == 0 {
		return 0, "", errors.New("GetExtendedUdpTable returned size 0")
	}

	buf := make([]byte, bufSize)
	ret, _, err := procGetExtendedUdpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufSize)),
		0,
		uintptr(AF_INET),
		uintptr(UDP_TABLE_OWNER_PID),
		0,
	)
	if ret != 0 {
		return 0, "", fmt.Errorf("GetExtendedUdpTable failed: %v (code %d)", err, ret)
	}

	// Buffer layout: DWORD dwNumEntries; then array of MIB_UDPROW_OWNER_PID entries.
	if len(buf) < 4 {
		return 0, "", errors.New("GetExtendedUdpTable returned too small buffer")
	}
	num := binary.LittleEndian.Uint32(buf[:4])
	const rowSize = 12 // MIB_UDPROW_OWNER_PID has 3 DWORDs = 12 bytes
	offset := 4
	for i := uint32(0); i < num; i++ {
		if offset+rowSize > len(buf) {
			break
		}
		localAddr := binary.LittleEndian.Uint32(buf[offset : offset+4])
		localPortRaw := binary.LittleEndian.Uint32(buf[offset+4 : offset+8])
		owningPid := binary.LittleEndian.Uint32(buf[offset+8 : offset+12])
		offset += rowSize

		// localPortRaw stores port in network byte order in low 16 bits.
		localPort := uint16(localPortRaw & 0xFFFF)
		localPort = (localPort>>8)&0xFF | (localPort&0xFF)<<8 // convert to host order

		// convert DWORD IP (little-endian) to net.IP
		ipb := []byte{
			byte(localAddr & 0xFF),
			byte((localAddr >> 8) & 0xFF),
			byte((localAddr >> 16) & 0xFF),
			byte((localAddr >> 24) & 0xFF),
		}
		entryIP := net.IPv4(ipb[0], ipb[1], ipb[2], ipb[3])

		//fmt.Println("Checking:",entryIP,ip4, localPort, port)

		if localPort == port {
			// treat 0.0.0.0 as wildcard match
			if entryIP.Equal(net.IPv4zero) || entryIP.Equal(ip4) {
				// found PID
				exe, err := exePathFromPID(owningPid)
				if err != nil {
					// got error due to permissions needed? this will work:
					exe = getProcessName(owningPid)
				}
				return owningPid, exe, nil
			}
		}
	}

	return 0, "", fmt.Errorf("pid %d not found for %s", num, clientAddr.String())
}

// exePathFromPID returns process image path for pid or an error.
// Uses QueryFullProcessImageNameW. May fail if insufficient privilege.
func exePathFromPID(pid uint32) (string, error) {
	const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	h, err := windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Errorf("OpenProcess failed: %w", err)
	}
	defer windows.CloseHandle(h)

	// prepare buffer for wide chars
	const bufChars = 260
	buf := make([]uint16, bufChars)
	size := uint32(bufChars)
	r1, _, e1 := procQueryFullProcessName.Call(
		uintptr(h),
		uintptr(0),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r1 == 0 {
		// try fallback: QueryFullProcessImageNameW may require different access; return PID only.
		return "", fmt.Errorf("QueryFullProcessImageNameW failed: %v", e1)
	}
	path := windows.UTF16ToString(buf[:size])
	// Normalize: make backslashes single and trim
	path = strings.TrimSpace(path)
	return path, nil
}

func getProcessName(pid uint32) string {
	// TH32CS_SNAPPROCESS = 0x00000002
	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(0x00000002, 0)
	if snapshot == uintptr(windows.InvalidHandle) {
		return "unknown"
	}
	defer windows.CloseHandle(windows.Handle(snapshot))

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, _ := procProcess32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	for ret != 0 {
		if entry.ProcessID == pid {
			return windows.UTF16ToString(entry.ExeFile[:])
		}
		ret, _, _ = procProcess32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	}
	return "not found"
}

// Example usage: call right after ReadFromUDP
func exampleUsage() {
	// suppose buf and udpLn are set and you just did:
	// n, clientAddr, err := udpLn.ReadFromUDP(buf)
	// then:
	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49936}
	pid, exe, err := PidAndExeForUDP(clientAddr)
	if err != nil {
		fmt.Println("lookup failed:", err)
	} else {
		fmt.Printf("PID %d exe %s\n", pid, exe)
	}
}
