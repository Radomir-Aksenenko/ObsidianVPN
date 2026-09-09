//go:build !linux

package main

import "io"

func openTUN(_ Config) io.ReadWriteCloser { return nil }
