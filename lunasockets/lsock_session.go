package lunasockets

import (
	"encoding/json"
	"fmt"
	"time"

	hdcrypto "github.com/fluffelpuff/HyperDirectory/crypto"
	"github.com/fxamacker/cbor/v2"
	"github.com/gorilla/websocket"
)

type LunaSocketSession struct {
	_master  *LunaSockets
	_ws_conn *websocket.Conn
}

// Wird verwendet um einen befehl innerhalb einer RPC Sitzung auszuführen
func (obj *LunaSocketSession) CallFunction(method string, parms []interface{}) ([]interface{}, error) {
	// Es wird eine Zuällige ID erzeugt
	rand_id := hdcrypto.RandomBase32Secret()

	// Das RPC Objekt wird gebaut
	rpc_object := RpcRequest{Method: method, Params: parms, JSONRPC: "2.0", ID: 1}

	b, err := json.Marshal(rpc_object)
	if err != nil {
		fmt.Println("Error marshalling:", err)
		return nil, err
	}

	// Das Reqeust Paket wird gebaut
	request_object := IoFlowPackage{Type: "rpc_request", Body: string(b), Id: rand_id}

	// Die Anfrage wird mittels CBOR umgewandelt
	data, err := cbor.Marshal(&request_object)
	if err != nil {
		return nil, err
	}

	// Diese Channel erhält die Antwort
	w_channel := make(chan RpcResponse)

	// Die Funktion welche aufgerufen wird sobald die Antwort erhalten wurde
	resolved_function := func(response RpcResponse) {
		w_channel <- response
	}

	// Die Sitzung wird Registriert
	obj._master._mu.Lock()
	obj._master._rpc_sessions[rand_id] = resolved_function
	obj._master._mu.Unlock()

	// Die Anfrage wird an den Server gesendet
	err = obj._ws_conn.WriteMessage(websocket.BinaryMessage, data)
	if err != nil {
		return nil, err
	}

	// Es wird auf die Antwort gewartet
	resolved_total := <-w_channel
	fmt.Println(resolved_total.Result)

	return nil, nil
}

// Wird verwendet um einen Ping zu senden
func (obj *LunaSocketSession) SendPing() (uint64, error) {
	// Es wird eine Zuällige ID erzeugt
	rand_id := hdcrypto.RandomBase32Secret()

	// Das Reqeust Paket wird gebaut
	request_object := IoFlowPackage{Type: "ping", Body: "PING", Id: rand_id}

	// Die Anfrage wird mittels CBOR umgewandelt
	data, err := cbor.Marshal(&request_object)
	if err != nil {
		return 0, err
	}

	// Die Aktuelle Zeit wird erfasst
	c_time := time.Now().Unix()

	// Diese Channel erhält die Antwort
	w_channel := make(chan uint64)

	// Die Funktion welche aufgerufen wird sobald die Antwort erhalten wurde
	resolved_function := func() {
		w_channel <- uint64(time.Now().Unix() - c_time)
	}

	// Die Sitzung wird Registriert
	obj._master._mu.Lock()
	obj._master._ping_sessions[rand_id] = resolved_function
	obj._master._mu.Unlock()

	// Die Anfrage wird an den Server gesendet
	err = obj._ws_conn.WriteMessage(websocket.BinaryMessage, data)
	if err != nil {
		return 0, err
	}

	// Es wird auf die Antwort gewartet
	resolved_total := <-w_channel

	// Die Zeit die dieser Ping benötigt hat, wird ermittelt
	return resolved_total, nil
}
