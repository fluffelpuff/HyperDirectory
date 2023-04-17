//go:build !wasm

package main

import (
	"fmt"
	"time"
)

func main() {
	_, err := CreateNewRPCClient("https://test.com:9001/jsonrpc")
	if err != nil {
		fmt.Println(err)
		return
	}
	for {
		time.Sleep(time.Millisecond * 1)
	}
}
