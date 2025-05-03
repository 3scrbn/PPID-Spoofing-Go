package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	targetProcess                        = "Notepad.exe"
	PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
)

var (
	kernel32                          = syscall.NewLazyDLL("kernel32.dll")
	initializeProcThreadAttributeList = kernel32.NewProc("InitializeProcThreadAttributeList")
	deleteProcThreadAttributeList     = kernel32.NewProc("DeleteProcThreadAttributeList")
	updateProcThreadAttribute         = kernel32.NewProc("UpdateProcThreadAttribute")
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <Parent Process Id>\n", os.Args[0])
	}

	pidStr := os.Args[1]
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		log.Fatalf("Invalid PID '%s': %v\n", pidStr, err)
	}

	dwParentPid := uint32(pid)

	hParentProcess, err := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS|windows.PROCESS_DUP_HANDLE, false, dwParentPid)
	if err != nil {
		log.Fatalf("OpenProcess for PID %d failed: %v\n", dwParentPid, err)
	}

	defer windows.CloseHandle(hParentProcess)
	fmt.Printf("[i] Creating target process '%s' with parent: %d\n", targetProcess, dwParentPid)

	dwProcessId, hProcess, hThread, err := createPPidSpoofedProcess(hParentProcess, targetProcess)
	if err != nil {
		log.Fatalf("createPPidSpoofedProcess failed: %v\n", err)
	}

	defer windows.CloseHandle(hProcess)
	defer windows.CloseHandle(hThread)

	fmt.Printf("[i] Target process created with PID: %d\n", dwProcessId)
}

func createPPidSpoofedProcess(hParentProcess windows.Handle, lpProcessName string) (dwProcessId uint32, hProcess windows.Handle, hThread windows.Handle, err error) {

	wnDir := os.Getenv("WINDIR")
	if wnDir == "" {
		return 0, 0, 0, fmt.Errorf("could not get WINDIR environment variable")
	}

	lpPath := filepath.Join(wnDir, "System32", lpProcessName)
	currentDir := filepath.Join(wnDir, "System32")

	var siEx windows.StartupInfoEx
	var pi windows.ProcessInformation

	siEx.StartupInfo.Cb = uint32(unsafe.Sizeof(siEx))
	var size uintptr

	_, _, _ = initializeProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))

	attributeListBytes := make([]byte, size)
	pThreadAttList := (*windows.ProcThreadAttributeList)(unsafe.Pointer(&attributeListBytes[0]))

	_, _, err = initializeProcThreadAttributeList.Call(uintptr(unsafe.Pointer(pThreadAttList)), 1, 0, uintptr(unsafe.Pointer(&size)))
	if err != windows.SEVERITY_SUCCESS {
		return 0, 0, 0, fmt.Errorf("InitializeProcThreadAttributeList (2nd call) failed: %w", err)
	}

	defer deleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(pThreadAttList)))

	_, _, err = updateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(pThreadAttList)),
		0,
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		uintptr(unsafe.Pointer(&hParentProcess)),
		unsafe.Sizeof(hParentProcess),
		0,
		0,
	)
	if err != windows.SEVERITY_SUCCESS {
		return 0, 0, 0, fmt.Errorf("UpdateProcThreadAttribute failed: %w", err)
	}

	siEx.ProcThreadAttributeList = pThreadAttList

	lpPathPtr, err := windows.UTF16PtrFromString(lpPath)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("StringToUTF16Ptr (lpPath) failed: %w", err)
	}
	currentDirPtr, err := windows.UTF16PtrFromString(currentDir)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("StringToUTF16Ptr (currentDir) failed: %w", err)
	}

	creationFlags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_NEW_CONSOLE)

	err = windows.CreateProcess(
		nil,               // lpApplicationName
		lpPathPtr,         // lpCommandLine
		nil,               // lpProcessAttributes
		nil,               // lpThreadAttributes
		false,             // bInheritHandles
		creationFlags,     // dwCreationFlags
		nil,               // lpEnvironment
		currentDirPtr,     // lpCurrentDirectory
		&siEx.StartupInfo, // lpStartupInfo
		&pi,               // lpProcessInformation
	)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("CreateProcess failed: %w", err)
	}

	dwProcessId = pi.ProcessId
	hProcess = pi.Process
	hThread = pi.Thread

	if dwProcessId != 0 && hProcess != 0 && hThread != 0 {
		return dwProcessId, hProcess, hThread, nil
	}

	if hProcess != 0 {
		windows.CloseHandle(hProcess)
	}
	if hThread != 0 {
		windows.CloseHandle(hThread)
	}
	return 0, 0, 0, fmt.Errorf("unexpected failure after CreateProcess, missing process data")
}
