//go:build wasm

package main

import "syscall/js"

func main() {
	// Die Basis Funktionen werden registriert
	js.Global().Set("hdlib", js.FuncOf(CreateNewRPCClientWrapper))
}
