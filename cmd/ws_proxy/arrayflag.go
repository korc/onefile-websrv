package main

import "strings"

type ArrayFlag []string

func (f *ArrayFlag) String() string {
	return strings.Join(*f, ", ")
}

func (f *ArrayFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}
