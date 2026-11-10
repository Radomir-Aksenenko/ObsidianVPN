//go:build !linux

package main

import (
	"errors"
	"os"
)

func openTUN(string) (*os.File, error) { return nil, errors.New("real TUN mode is Linux only") }
