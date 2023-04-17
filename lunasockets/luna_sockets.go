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
	_stream_sessions map[string]LunaPingResponseFunction
	_ping_sessions   map[string]LunaPingResponseFunction
	_rpc_sessions    map[string]LunaRpcResponseFunction
	_json_rpc_server *rpc.Server
	_upgrader        *websocket.Upgrader
	_mu              sync.Mutex
}

type LunaServerSession struct {
	Session LunaSocketSession
	_mother *LunaSockets
}

// Wird auf einer Serversitzung verwendet um Daten zu empfangen
func (obj *LunaServerSession) Serve() error {
	return obj._mother._wrappWS(obj.Session._ws_conn)
}

// Registriert ein neues Service Objekt
func (obj *LunaSockets) RegisterService(service_object any) error {
	return obj._json_rpc_server.Register(service_object)
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

// Diese Funktion wird ausgeführt um eine Serverseitige Verbindung zu Upgraden und eine LunaSocketSession Objekt zurückzugeben
func (obj *LunaSockets) UpgradeHTTPToLunaWebSocket(w http.ResponseWriter, r *http.Request) (LunaServerSession, error) {
	// upgrade the HTTP connection to a WebSocket connection
	ws, err := obj._upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Fatal("upgrade error:", err)
	}

	// Das Session Objekt wird erzeugt
	session_pbj := LunaSocketSession{_master: obj, _ws_conn: ws}

	// Das Serverseitige Sitzungsobjekt wird erzeugt
	server_obj := LunaServerSession{Session: session_pbj, _mother: obj}

	// Die Sitzung wird zurückgegeben
	return server_obj, nil
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
	new_obj._json_rpc_server = rpc.NewServer()
	new_obj._rpc_sessions = make(map[string]LunaRpcResponseFunction)
	new_obj._ping_sessions = make(map[string]LunaPingResponseFunction)
	new_obj._stream_sessions = make(map[string]LunaPingResponseFunction)
	new_obj._upgrader = &websocket.Upgrader{ReadBufferSize: 1024, WriteBufferSize: 1024}
	return new_obj
}
