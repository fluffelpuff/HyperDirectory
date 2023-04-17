package lunasockets

import (
	"encoding/json"
	"fmt"

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
	obj._master._sessions[rand_id] = resolved_function
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

// Wird verwendet um eine Verbindung mit einem Stream herzustellen
func (obj *LunaSocketSession) OpenStreamSession(port uint64) error {
	return nil
}

// Wird verwendet um einen Ping zu senden
func (obj *LunaSocketSession) SendPing() error {
	return nil
}
