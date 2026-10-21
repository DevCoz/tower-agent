//go:build !linux

package main

import (
	"context"
	"errors"
)

func rootLinux() bool                           { return false }
func lockAgent(string, bool) (func(), error)    { return nil, errors.New("Linux is required") }
func readToken(context.Context) (string, error) { return "", errors.New("Linux is required") }
