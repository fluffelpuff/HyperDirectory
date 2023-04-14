package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
)

// Stellt das Client Objekt dar
type RpcClient struct {
	_serverURL         string
	_clientCertKeyPair *tls.Certificate
	_cerPool           *x509.CertPool
}

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

// Erstellt eine neuen RPC_CLIENT
func CreateNewRPCClient(url string) (*RpcClient, error) {
	// Laden des Client-Zertifikats und Schlüssels
	cert, err := tls.LoadX509KeyPair("resc/test.com_client.crt", "resc/test.com_client.pem")
	if err != nil {
		log.Fatal("Error loading client certificate and key: ", err)
	}

	// Laden der Root-CA des Servers
	caCert, err := os.ReadFile("resc/DGPRootCA.crt")
	if err != nil {
		log.Fatal("Error reading server CA certificate: ", err)
	}

	// Der CA Pool wird vorbereitet
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Konfiguration des TLS-Clients
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	// Der JSON Request wird vorbereitet
	var resp RpcResponse
	anySlice := make([]interface{}, 0)
	// Der JSON Request wird abgesendet
	resp, err = _write_json_https_request(tlsConfig, url, "RPC.Hello", anySlice)
	if err != nil {
		return nil, fmt.Errorf("CreateNewRPCClient: " + err.Error())
	}

	// Wird geprüft ob ein Hallo Zurückgesendet wurde
	if _, ok := resp.Result.(string); ok {
		return nil, fmt.Errorf("CreateNewRPCClient: invalid response from server")
	}

	// Der Rückgabewert wird erzeugt
	res_value := RpcClient{_serverURL: url, _cerPool: caCertPool, _clientCertKeyPair: &cert}

	// Das Objekt wurde erfolgreich fertigestellt
	return &res_value, nil
}
