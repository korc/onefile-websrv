//go:build !windows

package main

import "syscall"

var canChroot = true
var canSetregid = true
var canSetreuid = true

func Chroot(dir string) error {
	return syscall.Chroot(dir)
}

func Setregid(rgid, egid int) error {
	return syscall.Setregid(rgid, egid)
}

func Setreuid(ruid, euid int) error {
	return syscall.Setreuid(ruid, euid)
}
