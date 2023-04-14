//go:build !wasm

package main

import (
	"fmt"
)

func main() {
	fmt.Println("TEST")
	_, err := CreateNewRPCClient("https://test.com:9001/jsonrpc")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("JOLO")
}
