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
	DecisionNone Decision = iota
	DecisionAllow
	DecisionDeny
	DecisionIgnore
)

const (
	WM_DESTROY = 0x0002
	WM_COMMAND = 0x0111
	WM_TIMER   = 0x0113
	WM_APP     = 0x8000

	WS_POPUP   = 0x80000000
	WS_VISIBLE = 0x10000000

	WS_EX_TOPMOST    = 0x00000008
	WS_EX_TOOLWINDOW = 0x00000080
	WS_EX_NOACTIVATE = 0x08000000

	BS_PUSHBUTTON = 0x00000000
	WS_CHILD      = 0x40000000

	SW_SHOW = 5
)

var (
	user32                   = syscall.NewLazyDLL("user32.dll")
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procCreateWindowExW      = user32.NewProc("CreateWindowExW")
	procDefWindowProcW       = user32.NewProc("DefWindowProcW")
	procDispatchMessageW     = user32.NewProc("DispatchMessageW")
	procGetMessageW          = user32.NewProc("GetMessageW")
	procPostQuitMessage      = user32.NewProc("PostQuitMessage")
	procRegisterClassExW     = user32.NewProc("RegisterClassExW")
	procSetTimer             = user32.NewProc("SetTimer")
	procEnableWindow         = user32.NewProc("EnableWindow")
	procSetWindowTextW       = user32.NewProc("SetWindowTextW")
	procGetSystemMetrics     = user32.NewProc("GetSystemMetrics")
	procShowWindow           = user32.NewProc("ShowWindow")
	procUpdateWindow         = user32.NewProc("UpdateWindow")
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
	resultChan      chan Decision
	buttonsEnabled  bool
	textLabel       uintptr
	buttonAllow     uintptr
	buttonDeny      uintptr
	buttonLookup    uintptr
	buttonIgnore    uintptr
)

func wndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {

	case WM_TIMER:
		enableButtons(true)
		return 0

	case WM_COMMAND:
		switch wParam & 0xffff {
		case 1:
			resultChan <- DecisionAllow
		case 2:
			resultChan <- DecisionDeny
		case 3:
			go func() {
				time.Sleep(500 * time.Millisecond)
				procSetWindowTextW.Call(
					textLabel,
					uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(
						"Lookup complete.\nThis domain appears safe."))),
				)
				enableButtons(true)
			}()
			enableButtons(false)
			return 0
		case 4:
			resultChan <- DecisionIgnore
		}
		procPostQuitMessage.Call(0)
		return 0

	case WM_DESTROY:
		procPostQuitMessage.Call(0)
		return 0
	}

	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
}

func enableButtons(enable bool) {
	if buttonsEnabled == enable {
		return
	}
	buttonsEnabled = enable
	flag := uintptr(0)
	if enable {
		flag = 1
	}
	procEnableWindow.Call(buttonAllow, flag)
	procEnableWindow.Call(buttonDeny, flag)
	procEnableWindow.Call(buttonLookup, flag)
	procEnableWindow.Call(buttonIgnore, flag)
}

func showDialog(ch chan Decision) {
	resultChan = ch

	className := syscall.StringToUTF16Ptr("GoDemoDialog")

	wc := WNDCLASSEX{
		cbSize:        uint32(unsafe.Sizeof(WNDCLASSEX{})),
		lpfnWndProc:   syscall.NewCallback(wndProc),
		hInstance:     syscall.Handle(0),
		lpszClassName: className,
	}

	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	screenW, _, _ := procGetSystemMetrics.Call(0)
	screenH, _, _ := procGetSystemMetrics.Call(1)

	width := int32(360)
	height := int32(180)
	x := int32(screenW) - width - 20
	y := int32(screenH) - height - 40

	hwnd, _, _ := procCreateWindowExW.Call(
		WS_EX_TOPMOST|WS_EX_TOOLWINDOW|WS_EX_NOACTIVATE,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("DNS Request"))),
		WS_POPUP|WS_VISIBLE,
		uintptr(x), uintptr(y),
		uintptr(width), uintptr(height),
		0, 0, 0, 0,
	)

	textLabel, _, _ = procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("STATIC"))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(
			"Allow DNS request to:\nexample.com ?"))),
		WS_CHILD|WS_VISIBLE,
		10, 10, 330, 60,
		hwnd, 0, 0, 0,
	)

	buttonAllow = createButton(hwnd, "Allow", 10, 80, 80, 24, 1)
	buttonDeny = createButton(hwnd, "Deny", 100, 80, 80, 24, 2)
	buttonLookup = createButton(hwnd, "Look It Up", 190, 80, 100, 24, 3)
	buttonIgnore = createButton(hwnd, "Ignore", 130, 120, 80, 24, 4)

	enableButtons(false)
	procSetTimer.Call(hwnd, 1, 1000, 0)

	procShowWindow.Call(hwnd, SW_SHOW)
	procUpdateWindow.Call(hwnd)

	var msg MSG
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func createButton(parent uintptr, text string, x, y, w, h int32, id uintptr) uintptr {
	btn, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("BUTTON"))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(text))),
		WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		parent, id, 0, 0,
	)
	return btn
}

func main() {
	ch := make(chan Decision, 1)

	go showDialog(ch)

	// Comment this line out if you *don't* want to wait
	decision := <-ch

	fmt.Println("Decision:", decision)
}
