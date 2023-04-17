package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"runtime"
)

// Stellt den RPC Response dar
type RpcResponse struct {
	Result  interface{} `json:"result"`
	Error   interface{} `json:"error"`
	ID      int         `json:"id"`
	JSONRPC string      `json:"jsonrpc"`
}

// Sendet eine JSON-HTTP-RPC Anfrage ab (wird bei Nativer ausführung verwendet)
func _write_json_https_request_native(tls_config *tls.Config, url string, function_name string, parms []interface{}) (RpcResponse, error) {
	// Die Payload wird vorbereitet
	payload, err := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "method": function_name, "params": parms, "id": 1})
	if err != nil {
		log.Fatal("Error encoding JSON-RPC request: ", err)
	}

	// Der JSON Request wird vorbereitet
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		log.Fatal("Error creating HTTP request: ", err)
	}
	req.Header.Set("Content-Type", "application/json")

	transport := &http.Transport{TLSClientConfig: tls_config}
	client := &http.Client{Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Error sending HTTP request: ", err)
	}
	defer func() {
		resp.Body.Close()
	}()

	var response RpcResponse
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&response)
	if err != nil {
		log.Fatal("Error decoding JSON-RPC response: ", err)
	}

	if response.Error != nil {
		log.Fatal("JSON-RPC error: ", response.Error)
	}

	return response, nil
}

// Sendet eine JSON-HTTP-RPC Anfrage ab (wird bei der Ausführung im Browser verwendet)
func _write_json_https_request_web(tls_config *tls.Config, url string, function_name string, parms []interface{}) (RpcResponse, error) {
	return RpcResponse{}, nil
}

// Sendet eine JSON-HTTP-RPC Anfrage ab
func _write_json_https_request(tls_config *tls.Config, url string, function_name string, parms []interface{}) (RpcResponse, error) {
	// Es wird geprüftob der Code als WASM oder Nativ ausgeführt wird
	if runtime.GOARCH == "wasm" {
		// Es wird geprüft ob der Code in einer JavaScript umgebung ausgeführt wird
		if runtime.GOOS == "js" {
			// Die Webconfig wird aufgerufen
			return _write_json_https_request_web(tls_config, url, function_name, parms)
		} else {
			// Die Native Funktion wird verwendet
			return _write_json_https_request_native(tls_config, url, function_name, parms)
		}
	} else {
		// Die Native Funktion wird verwendet
		return _write_json_https_request_native(tls_config, url, function_name, parms)
	}
}
