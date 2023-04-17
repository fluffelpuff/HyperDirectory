package lunasockets

import (
	"fmt"
	"log"
	"net/http"
	"net/rpc"
	"sync"

	"github.com/gorilla/websocket"
)

type LunaSockets struct {
	_mu              sync.Mutex
	_sessions        map[string]LunaRpcResponseFunction
	_upgrader        *websocket.Upgrader
	_json_rpc_server *rpc.Server
}

// Registriert ein neues Service Objekt
func (obj *LunaSockets) RegisterService(service_object any) error {
	return obj._json_rpc_server.Register(service_object)
}

// Erstellt einen neuen Stream
func (obj *LunaSockets) CreateNewStream(port uint64) error {
	return nil
}

// Diese Funktion wird ausgeführt sobald eine neue Verbindung aufgebaut wurde
func (obj *LunaSockets) ServeHTTPToWebSocket(w http.ResponseWriter, r *http.Request) {
	// upgrade the HTTP connection to a WebSocket connection
	ws, err := obj._upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Fatal("upgrade error:", err)
	}

	// Die WS Funktion wird aufgerufen
	if err := obj._wrappWS(ws); err != nil {
		fmt.Println(err)
	}
}

// Diese Funktion wird auf der Clientseite verwendet
func (obj *LunaSockets) WrappWS(conn *websocket.Conn) (LunaSocketSession, error) {
	// Der WS_Connection Wrapper wird gestartet
	go func() {
		if err := obj._wrappWS(conn); err != nil {
			fmt.Println(err)
		}
	}()

	// Das Sitzungsobjekt wird erzeugt
	session_pbj := new(LunaSocketSession)
	session_pbj._master = obj
	session_pbj._ws_conn = conn
	return *session_pbj, nil
}

// Erstellt das neue Objekt
func NewLunaSocket() *LunaSockets {
	new_obj := new(LunaSockets)
	new_obj._sessions = make(map[string]LunaRpcResponseFunction)
	new_obj._json_rpc_server = rpc.NewServer()
	new_obj._upgrader = &websocket.Upgrader{ReadBufferSize: 1024, WriteBufferSize: 1024}
	return new_obj
}
