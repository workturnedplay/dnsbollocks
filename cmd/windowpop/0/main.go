//go:build windows
// +build windows

package main

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

type Decision int

const (
	DecisionAllow Decision = iota + 1
	DecisionDeny
	DecisionLookup
	DecisionIgnore
)

const (
	WM_DESTROY = 0x0002
	WM_COMMAND = 0x0111
	WM_TIMER   = 0x0113

	WS_POPUP   = 0x80000000
	WS_VISIBLE = 0x10000000
	WS_CHILD   = 0x40000000

	WS_EX_TOPMOST    = 0x00000008
	WS_EX_TOOLWINDOW = 0x00000080
	WS_EX_NOACTIVATE = 0x08000000

	BS_PUSHBUTTON = 0x00000000
	SW_SHOW       = 5
)

var (
	user32               = syscall.NewLazyDLL("user32.dll")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procSetTimer         = user32.NewProc("SetTimer")
	procEnableWindow     = user32.NewProc("EnableWindow")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")
)

type WNDCLASSEX struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     syscall.Handle
	hIcon         syscall.Handle
	hCursor       syscall.Handle
	hbrBackground syscall.Handle
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       syscall.Handle
}

type MSG struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      struct{ x, y int32 }
}

var (
	resultCh  chan Decision
	textLabel uintptr
	btns      []uintptr
)

func wndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {

	case WM_TIMER:
		for _, b := range btns {
			procEnableWindow.Call(b, 1)
		}
		return 0

	case WM_COMMAND:
		// low word of wParam is control id
		id := int(wParam & 0xffff)
		switch Decision(id) {
		case DecisionLookup:
			// simulate async lookup: disable buttons, change text, re-enable later
			for _, b := range btns {
				procEnableWindow.Call(b, 0)
			}
			go func() {
				time.Sleep(600 * time.Millisecond) // pretend we're doing work
				newText := "Lookup complete.\nThis domain appears safe."
				procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("STATIC"))),
					uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(newText))),
					WS_CHILD|WS_VISIBLE,
					10, 10, 330, 40,
					hwnd, 0, 0, 0) // quick-and-dirty: replace static (simpler than SetWindowText here)
				// re-enable buttons
				for _, b := range btns {
					procEnableWindow.Call(b, 1)
				}
			}()
			return 0
		default:
			resultCh <- Decision(id)
			procPostQuitMessage.Call(0)
			return 0
		}

	case WM_DESTROY:
		procPostQuitMessage.Call(0)
		return 0
	}

	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
}

func showDialog(ch chan Decision) {
	resultCh = ch

	className := syscall.StringToUTF16Ptr("GoWin32Demo")

	wc := WNDCLASSEX{
		cbSize:        uint32(unsafe.Sizeof(WNDCLASSEX{})),
		lpfnWndProc:   syscall.NewCallback(wndProc),
		hbrBackground: syscall.Handle(6), // COLOR_BTNFACE+1
		lpszClassName: className,
	}

	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	screenW, _, _ := procGetSystemMetrics.Call(0)
	screenH, _, _ := procGetSystemMetrics.Call(1)

	w, h := int32(360), int32(170)
	x := int32(screenW) - w - 20
	y := int32(screenH) - h - 40

	hwnd, _, _ := procCreateWindowExW.Call(
		WS_EX_TOPMOST|WS_EX_TOOLWINDOW|WS_EX_NOACTIVATE,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("DNS Request"))),
		WS_POPUP|WS_VISIBLE,
		uintptr(x), uintptr(y),
		uintptr(w), uintptr(h),
		0, 0, 0, 0,
	)

	// static text
	textLabel, _, _ = procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("STATIC"))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Allow DNS request to example.com?"))),
		WS_CHILD|WS_VISIBLE,
		10, 10, 330, 40,
		hwnd, 0, 0, 0,
	)

	// create buttons (ids are Decision values)
	btns = append(btns,
		createButton(hwnd, "Allow", 10, 70, 70, 24, DecisionAllow),
		createButton(hwnd, "Deny", 90, 70, 70, 24, DecisionDeny),
		createButton(hwnd, "Lookup", 170, 70, 80, 24, DecisionLookup),
		createButton(hwnd, "Ignore", 260, 70, 70, 24, DecisionIgnore),
	)

	// disable buttons, enable after 1s
	for _, b := range btns {
		procEnableWindow.Call(b, 0)
	}
	procSetTimer.Call(hwnd, 1, 1000, 0)

	var msg MSG
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func createButton(parent uintptr, text string, x, y, w, h int32, id Decision) uintptr {
	btn, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("BUTTON"))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(text))),
		WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		parent, uintptr(id), 0, 0,
	)
	return btn
}

func main() {
	ch := make(chan Decision, 1)
	go showDialog(ch)

	// wait for choice (remove receive if you don't want to block)
	decision := <-ch
	fmt.Println("Decision:", decision)
	time.Sleep(200 * time.Millisecond) // slight pause so console stays visible
}
