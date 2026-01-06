//go:build !windows
// +build !windows

//why this? to silence CodeQL warning:
//"An imported package is intended for a different OS or architecture
//golang.org/x/sys/windows could not be imported. Make sure the GOOS and GOARCH environment variables are correctly set. Alternatively, change your OS and architecture."

package dnsbollocks

func OldMain() {
	panic("dnsbollocks is Windows-only")
}
