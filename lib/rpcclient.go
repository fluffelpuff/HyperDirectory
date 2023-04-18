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

	// Die URL wird geprüft
	_, err = url.Parse(url_str)
	if err != nil {
		log.Fatal(err)
	}

	// Die Websocketverbindung wird aufgebaut
	dialer := &websocket.Dialer{TLSClientConfig: tlsConfig}
	conn, response, err := dialer.Dial("wss://test.com:9001/wsrpc", nil)
	if err != nil {
		log.Fatal(err)
	}

	// Der HWS Client wird erzeugt
	hws := lunasockets.NewLunaSocket()
	fmt.Println(&response.Header)
	sess, err := hws.ClientServeWrappWS(conn, &response.Header)
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
	return nil, nil
}
