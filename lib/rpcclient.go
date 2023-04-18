package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/url"
	"os"

	"github.com/fluffelpuff/HyperDirectory/lunasockets"
	"github.com/gorilla/websocket"
)

// Stellt das Client Objekt dar
type RpcClient struct {
	_serverURL         string
	_tlsConfig         *tls.Config
	_clientCertKeyPair *tls.Certificate
	_cerPool           *x509.CertPool
}

// Erstellt eine neuen RPC_CLIENT
func CreateNewRPCClient(url_str string) (*RpcClient, error) {
	// Laden des Client-Zertifikats und Schlüssels
	cert, err := tls.LoadX509KeyPair("../resc/test.com_client.crt", "../resc/test.com_client.pem")
	if err != nil {
		log.Fatal("Error loading client certificate and key: ", err)
	}

	// Laden der Root-CA des Servers
	caCert, err := os.ReadFile("../resc/DGPRootCA.crt")
	if err != nil {
		log.Fatal("Error reading server CA certificate: ", err)
	}

	// Der CA Pool wird vorbereitet
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Konfiguration des TLS-Clients
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: caCertPool}

	// Der JSON Request wird vorbereitet
	var resp RpcResponse
	anySlice := make([]interface{}, 0)

	// Der JSON Request wird abgesendet
	resp, err = _write_json_https_request(tlsConfig, url_str, "RPC.Hello", anySlice)
	if err != nil {
		return nil, fmt.Errorf("CreateNewRPCClient: 1:" + err.Error())
	}

	// Wird geprüft ob ein Hallo Zurückgesendet wurde
	vret, ok := resp.Result.(string)
	if !ok {
		return nil, fmt.Errorf("CreateNewRPCClient: invalid response from server #" + vret)
	}

	// Der Rückgabewert wird erzeugt
	res_value := RpcClient{_serverURL: url_str, _cerPool: caCertPool, _clientCertKeyPair: &cert, _tlsConfig: tlsConfig}

	// Die Websocketverbindung wird aufgebaut
	_, err = url.Parse(url_str)
	if err != nil {
		log.Fatal(err)
	}

	dialer := &websocket.Dialer{TLSClientConfig: tlsConfig}
	conn, _, err := dialer.Dial("wss://test.com:9001/wsrpc", nil)
	if err != nil {
		log.Fatal(err)
	}

	// Der HWS Client wird erzeugt
	hws := lunasockets.NewLunaSocket()
	sess, err := hws.ServeWrappWS(conn)
	if err != nil {
		fmt.Println(err)
	}
	params := make([]interface{}, 1)
	for i, v := range []lunasockets.TestObject{lunasockets.TestObject{Value: "a"}} {
		params[i] = v
	}
	sess.CallFunction("User.TestFunction", params)
	sess.SendPing()
	fmt.Println("YOLO")

	// Das Objekt wurde erfolgreich fertigestellt
	return &res_value, nil
}
