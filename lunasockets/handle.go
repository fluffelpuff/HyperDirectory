package lunasockets

import (
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/gorilla/websocket"
)

// Diese Funktion wird ausgeführt wenn es sich um ein RPC Request handelt
func (obj *LunaSockets) _handleRPC(conn *websocket.Conn, id string, rpc_data RpcRequest) error {
	// Das Codec für den Request wird vorbereitet
	req := &RpcRequestCodec{data: rpc_data, closed: false}
	if err := obj._json_rpc_server.ServeRequest(req); err != nil {
		fmt.Println("DD:", err)
	}

	// Die Antwort wird ausgelesen
	resolv, err := req.GetResponse()
	if err != nil {
		return err
	}

	// Die Antwort wird zurückgesendet
	response := RpcResponse{Result: resolv, Error: nil}

	// Die Daten werden mit JSON codiert
	un, err := json.Marshal(response)
	if err != nil {
		return err
	}

	// Die Antwort wird vorbereitet
	resolve := IoFlowPackage{Type: "rpc_response", Id: id, Body: string(un)}

	// Die Date werden mittels CBOR Codiert
	data, err := cbor.Marshal(&resolve)
	if err != nil {
		return err
	}

	// Die Daten werden an die gegenseite gesendet
	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return err
	}

	// Die Antwort wird zurückgegeben
	return nil
}

// Diese Funktion ließt aus den WS aus
func (obj *LunaSockets) _wrappWS(conn *websocket.Conn) error {
	// Diese Funktion wird ausgeführt um eintreffende Nachrichten zu lesen
	loop_end := false
	for !loop_end {
		// Es wird geprüft ob es sich um einen Zulässigen Typen handelt
		typ, data, err := conn.ReadMessage()
		if err != nil {
			loop_end = true
			return err
		}
		if typ != websocket.BinaryMessage {
			fmt.Println("Data type")
		}

		// Die Daten werden versucht einzulesen
		var msg FirstCheck
		err = cbor.Unmarshal(data, &msg)
		if err != nil {
			fmt.Println(err)
		}

		// Es wird geprüft ob eine ID und ein Type vorhanden ist
		if len(msg.Id) == 0 || len(msg.Type) == 0 {
			fmt.Println("INVALID_PACKAGE")
		}

		// Es wird geprüft um was für ein Pakettypen es sich handelt
		switch msg.Type {
		case "rpc_request":
			// Das Paket wird neu eingelesen
			var complete_package IoFlowPackage
			err = cbor.Unmarshal(data, &complete_package)
			if err != nil {
				fmt.Println(err)
			}

			// Das RPC Objekt wird eingelesen
			var readed_rpc_req RpcRequest
			if err := json.Unmarshal([]byte(complete_package.Body), &readed_rpc_req); err != nil {
				fmt.Println(err)
				continue
			}

			// Die Daten werden an die RPC Handle Funktion übergeben
			go func(xconn *websocket.Conn) {
				if err := obj._handleRPC(conn, complete_package.Id, readed_rpc_req); err != nil {
					fmt.Println(err)
				}
			}(conn)
		case "rpc_response":
			// Es wird geprüft ob es eine Sitzung mit dieser Id gibt
			obj._mu.Lock()
			resolved, ok := obj._sessions[msg.Id]
			if !ok {
				obj._mu.Unlock()
				fmt.Println("UNKOWN_SESSION")
				continue
			}

			// Das Paket wird neu eingelesen
			var complete_package IoFlowPackage
			err = cbor.Unmarshal(data, &complete_package)
			if err != nil {
				obj._mu.Unlock()
				fmt.Println(err)
				continue
			}

			// Das Paket wird eingelesen
			var readed_response RpcResponse
			if err := json.Unmarshal([]byte(complete_package.Body), &readed_response); err != nil {
				fmt.Println(err)
				obj._mu.Unlock()
				continue
			}

			// Die ID wird wieder entfernt
			delete(obj._sessions, msg.Id)

			// Die Funktion wird in einem eigenen Thread aufgerufen
			go resolved(readed_response)
			obj._mu.Unlock()
		case "stream_request":
			continue
		case "stream_response":
			continue
		case "stream_data_request":
			continue
		case "stream_data_response":
			continue
		case "ping":
			continue
		case "pong":
			continue
		default:
			fmt.Println("CORRUPT_CONNECTION")
		}
	}

	return nil
}
