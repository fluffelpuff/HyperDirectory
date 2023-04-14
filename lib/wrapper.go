//go:build wasm

package main

import "syscall/js"

func CreateNewRPCClientWrapper(this js.Value, args []js.Value) interface{} {
	return nil
}
