package lunasockets

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/gorilla/websocket"
)

// Diese Funktion schreibt einen Fehler in eine Verbindung
func writeError(conn *websocket.Conn, id string, errstr string) error {
	// Die Antwort wird zurückgesendet
	response := RpcResponse{Result: nil, Error: &errstr}

	// Die Daten werden mit JSON Kodiert
	un, err := json.Marshal(response)
	if err != nil {
		return writeError(conn, id, "internal encoding error")
	}

	// Die Antwort wird vorbereitet
	resolve := IoFlowPackage{Type: "rpc_response", Id: id, Body: string(un)}

	// Die Date werden mittels CBOR Codiert
	data, err := cbor.Marshal(&resolve)
	if err != nil {
		return writeError(conn, id, "internal encoding error")
	}

	// Die Daten werden an die gegenseite gesendet
	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return fmt.Errorf("ws writing error")
	}

	// Der Vorgang wurde erfolgreich durchgeführt
	return nil
}

// Diese Funktion wird ausgeführt wenn es sich um ein RPC Request handelt
func (obj *LunaSockets) _handleRPC(conn *LunaSocketSession, id string, rpc_data RpcRequest) error {
	// Es wird geprüt ob es sich um einen Zuläsigen Methoden Namen handelt
	if !validateFunctionCall(rpc_data.Method) {
		return writeError(conn._ws_conn, id, "invalid function call")
	}

	// Es wird geprüft ob es sich um eine bekannte Service Funktion handelt
	ok, service := obj.isValidateServiceFunctionAndGetServiceObject(rpc_data.Method)
	if !ok {
		return writeError(conn._ws_conn, id, "unkown function")
	}

	// Der Name wird vorbereitet
	prep_name := getFunctionNameOfCall(rpc_data.Method)

	// Es wird geprüft ob die Variable nicht leer ist
	if len(prep_name) < 2 {
		return writeError(conn._ws_conn, id, "invalid function call")
	}

	// Das Request Objekt wird erzeugt
	req := new(Request)

	// Die Requestdaten werden ausgewertet
	if rpc_data.ProxyPass != nil {
		req.Header = rpc_data.ProxyPass
	} else {
		req.Header = conn._header
	}

	// Die Daten werden übertragen
	req.OutPassedArgs = append(req.OutPassedArgs, conn._passed_args...)

	// Die Funktion wird aufgerufen
	result, err := callServiceFunction(&Request{}, service, prep_name, rpc_data.Params)
	if err != nil {
		return writeError(conn._ws_conn, id, fmt.Sprintf("method '%s' calling error", rpc_data.Method))
	}

	// Die Antwort wird zurückgesendet
	response := RpcResponse{Result: result, Error: nil}

	// Die Daten werden mit JSON Kodiert
	un, err := json.Marshal(response)
	if err != nil {
		return writeError(conn._ws_conn, id, "internal encoding error")
	}

	// Die Antwort wird vorbereitet
	resolve := IoFlowPackage{Type: "rpc_response", Id: id, Body: string(un)}

	// Die Date werden mittels CBOR Codiert
	data, err := cbor.Marshal(&resolve)
	if err != nil {
		return writeError(conn._ws_conn, id, "internal encoding error")
	}

	// Die Daten werden an die gegenseite gesendet
	if err := conn._ws_conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return fmt.Errorf("ws writing error")
	}

	// Die Antwort wird zurückgegeben
	return nil
}

// Diese Funktion wird ausgeführt sobald ein Ping Paket eingetroffen ist
func (obj *LunaSockets) _handlePING(conn *LunaSocketSession, id string, ping_data string) error {
	// Es wird ein Pong Paket gebaut und an die gegenseite zurückgesendet
	request_object := IoFlowPackage{Type: "pong", Body: ping_data, Id: id}

	// Die Anfrage wird mittels CBOR umgewandelt
	data, err := cbor.Marshal(&request_object)
	if err != nil {
		return err
	}

	// Das Pong Paket wird zurück an den absendenen Client gesendet
	err = conn._ws_conn.WriteMessage(websocket.BinaryMessage, data)
	if err != nil {
		return err
	}

	// Es wird ein Log eintrag erzeugt
	log.Printf("pong '%s' send\n", id)

	// Der Vorgang wurde ohne fehler durchgeführt
	return nil
}

// Diese Funktion ließt aus den WS aus
func (obj *LunaSockets) _wrappWS(conn *LunaSocketSession) error {
	// Diese Funktion wird ausgeführt um eintreffende Nachrichten zu lesen
	loop_end := false
	for !loop_end {
		// Es wird geprüft ob es sich um einen Zulässigen Typen handelt
		typ, data, err := conn._ws_conn.ReadMessage()
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

			// Es wird der Log angezeigt dass ein RPC Request empfangen wurde
			log.Printf("rpc-request %s recived\n", complete_package.Id)

			// Die Daten werden an die RPC Handle Funktion übergeben
			go func(xconn *LunaSocketSession) {
				// Die Aktuelle Zeit wird erfasst
				start_time := time.Now().Unix()

				// Das RPC Handle wird ausgeführt
				if err := obj._handleRPC(conn, complete_package.Id, readed_rpc_req); err != nil {
					log.Fatalln("rpc-request '%s' connection error: " + err.Error())
				}

				// Es wird ausgerechnet wielange dieser Vorgang gedauert hat
				total_time := time.Now().Unix() - start_time
				log.Printf("rpc-request '%s' response finally send in %d seconds\n", complete_package.Id, total_time)
			}(conn)
		case "rpc_response":
			// Es wird geprüft ob es eine Sitzung mit dieser Id gibt
			obj._mu.Lock()
			resolved, ok := obj._rpc_sessions[msg.Id]
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

			// Es wird der Log angezeigt dass ein RPC Response empfangen wurde
			log.Printf("rpc-response recived %s\n", complete_package.Id)

			// Das Paket wird eingelesen
			var readed_response RpcResponse
			if err := json.Unmarshal([]byte(complete_package.Body), &readed_response); err != nil {
				fmt.Println(err)
				obj._mu.Unlock()
				continue
			}

			// Die ID wird wieder entfernt
			delete(obj._rpc_sessions, msg.Id)

			// Der Threadlock wird freigegeben
			obj._mu.Unlock()

			// Die Funktion wird in einem eigenen Thread aufgerufen
			go resolved(readed_response)
		case "ping":
			// Das Paket wird neu eingelesen
			var complete_package IoFlowPackage
			err = cbor.Unmarshal(data, &complete_package)
			if err != nil {
				fmt.Println(err)
			}

			// Es wird der Log angezeigt dass ein RPC Response empfangen wurde
			log.Printf("ping %s recived\n", complete_package.Id)

			// Der Ping Handler wird ausgeführt
			go obj._handlePING(conn, complete_package.Id, complete_package.Body)
		case "pong":
			// Es wird geprüft ob es eine Sitzung mit dieser Id gibt
			obj._mu.Lock()
			resolved, ok := obj._ping_sessions[msg.Id]
			if !ok {
				fmt.Println("W:", err)
				obj._mu.Unlock()
				fmt.Println("UNKOWN_SESSION")
				continue
			}

			// Das Paket wird neu eingelesen
			var complete_package IoFlowPackage
			err = cbor.Unmarshal(data, &complete_package)
			if err != nil {
				fmt.Println("Y:", err)
				obj._mu.Unlock()
				fmt.Println(err)
				continue
			}

			// Es wird der Log angezeigt dass ein Pong empfangen wurde
			log.Printf("pong %s recived\n", complete_package.Id)

			// Die ID wird wieder entfernt
			delete(obj._rpc_sessions, msg.Id)

			// Der Threadlock wird freigegeben
			obj._mu.Unlock()

			// Die Funktion wird in einem eigenen Thread aufgerufen
			go resolved()
		default:
			fmt.Println("CORRUPT_CONNECTION")
		}
	}

	return nil
}
