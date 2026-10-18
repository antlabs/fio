//go:build !linux

package engine

var pinEnabled = false

func enablePinning() {}

func pinLoop(int) {}
