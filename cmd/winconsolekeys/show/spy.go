//go:build windows

package main

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/term"
)

type inputRecord struct {
	EventType uint16
	_         [2]byte
	Event     [16]byte
}

type keyEventRecord struct {
	BKeyDown        int32
	RepeatCount     uint16
	VirtualKeyCode  uint16
	VirtualScanCode uint16
	UnicodeChar     uint16
	ControlKeyState uint32
}

type mouseEventRecord struct {
	X            int16
	Y            int16
	ButtonState  uint32
	ControlState uint32
	EventFlags   uint32
}

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procReadConsoleInputW = kernel32.NewProc("ReadConsoleInputW")
	procGetConsoleMode    = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode    = kernel32.NewProc("SetConsoleMode")
)

const (
	KEY_EVENT   = 0x0001
	MOUSE_EVENT = 0x0002

	ENABLE_LINE_INPUT = 0x0002
	ENABLE_ECHO_INPUT = 0x0004
)

func big() {
	h := syscall.Handle(os.Stdin.Fd())
	fmt.Println("Move mouse / press keys for 3 seconds…(or Ctrl+C to exit)")
	time.Sleep(3 * time.Second)

	var oldMode uint32
	r1, _, err := procGetConsoleMode.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&oldMode)),
	)
	if r1 == 0 {
		panic(err)
	}

	newMode := oldMode &^ (ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT)
	procSetConsoleMode.Call(uintptr(h), uintptr(newMode))
	defer procSetConsoleMode.Call(uintptr(h), uintptr(oldMode))

	fmt.Println("Console event spy running. Press keys, move mouse. (press 'd' key to quit to next stage, or Ctrl+C to exit)")

TheFor:
	for {
		var rec inputRecord
		var read uint32

		r1, _, err := procReadConsoleInputW.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(&rec)),
			1,
			uintptr(unsafe.Pointer(&read)),
		)
		if r1 == 0 {
			fmt.Println("ReadConsoleInputW error:", err)
			return
		}
		if read == 0 {
			continue
		}

		switch rec.EventType {
		case KEY_EVENT:
			ke := (*keyEventRecord)(unsafe.Pointer(&rec.Event[0]))
			vk := ke.VirtualKeyCode
			fmt.Printf(
				"KEY  down=%v vk=0x%X rune=%q ctrl=0x%X\n",
				ke.BKeyDown != 0,
				vk,
				rune(ke.UnicodeChar),
				ke.ControlKeyState,
			)
			if vk == 0x44 { // press 'd' key to quit
				break TheFor
			}

		case MOUSE_EVENT:
			me := (*mouseEventRecord)(unsafe.Pointer(&rec.Event[0]))
			fmt.Printf(
				"MOUSE x=%d y=%d buttons=0x%X flags=0x%X\n",
				me.X, me.Y, me.ButtonState, me.EventFlags,
			)

		default:
			fmt.Printf("EVENT type=0x%X\n", rec.EventType)
		}
	}
}

func main() {
	// so, can mix events and os.Stdin.Read
	for repeat := 0; repeat < 2; repeat++ {
		big()

		fd := int(os.Stdin.Fd())
		oldState, err := term.MakeRaw(fd)
		if err != nil {
			fmt.Print("couldn't make the terminal raw, bailing!")
			return // or log, or fail loudly — your call
		}
		defer term.Restore(fd, oldState)

		fmt.Print("Now press any key to exit.")
		ReadKeySequence()
		fmt.Println()
		term.Restore(fd, oldState)
	}

}
func ReadKeySequence() {
	var b [1]byte
	_, _ = os.Stdin.Read(b[:])
}

// package main

// import (
// 	"fmt"
// 	"os"

// 	"golang.org/x/sys/windows"
// )

// func main() {
// 	h := windows.Handle(os.Stdin.Fd())

// 	var oldMode uint32
// 	if err := windows.GetConsoleMode(h, &oldMode); err != nil {
// 		panic(err)
// 	}

// 	// Disable line input and echo so we get raw key events
// 	newMode := oldMode
// 	newMode &^= windows.ENABLE_LINE_INPUT
// 	newMode &^= windows.ENABLE_ECHO_INPUT

// 	if err := windows.SetConsoleMode(h, newMode); err != nil {
// 		panic(err)
// 	}
// 	defer windows.SetConsoleMode(h, oldMode)

// 	fmt.Println("Console event spy running.")
// 	fmt.Println("Press keys, move mouse, Ctrl+C to exit.")

// 	for {
// 		var rec windows.InputRecord
// 		var read uint32

// 		err := windows.ReadConsoleInput(h, &rec, 1, &read)
// 		if err != nil {
// 			fmt.Println("ReadConsoleInput error:", err)
// 			return
// 		}
// 		if read == 0 {
// 			continue
// 		}

// 		switch rec.EventType {
// 		case windows.KEY_EVENT:
// 			ke := rec.KeyEvent
// 			fmt.Printf(
// 				"KEY  down=%v  vk=0x%02X  rune=%q  ctrl=0x%X\n",
// 				ke.BKeyDown,
// 				ke.VirtualKeyCode,
// 				ke.UnicodeChar,
// 				ke.ControlKeyState,
// 			)

// 		case windows.MOUSE_EVENT:
// 			me := rec.MouseEvent
// 			fmt.Printf(
// 				"MOUSE x=%d y=%d buttons=0x%X flags=0x%X\n",
// 				me.MousePosition.X,
// 				me.MousePosition.Y,
// 				me.ButtonState,
// 				me.EventFlags,
// 			)

// 		default:
// 			fmt.Printf("EVENT type=0x%X\n", rec.EventType)
// 		}
// 	}
// }
