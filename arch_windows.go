//go:build windows

package main

var canChroot = false
var canSetregid = false
var canSetreuid = false

func Chroot(dir string) error {
	panic("chroot not implemented")
}

func Setregid(rgid, egid int) error {
	panic("setregid not implemented")
}

func Setreuid(ruid, euid int) error {
	panic("setreuid not implemented")
}
