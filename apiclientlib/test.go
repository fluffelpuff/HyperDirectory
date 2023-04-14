///go:build test

package main

import "fmt"

func main() {
	_, err := CreateNewRPCClient("https://test.com:9001/jsonrpc")
	if err != nil {

	}
	fmt.Println("JOLO")
}
