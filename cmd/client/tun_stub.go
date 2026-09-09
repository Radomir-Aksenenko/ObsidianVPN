//go:build !windows

package main

import "io"

func openTUN(_ Config) io.ReadWriteCloser { return nil }
