package lunasockets

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

type LunaSockets struct {
	_ping_sessions map[string]LunaPingResponseFunction
	_rpc_sessions  map[string]LunaRpcResponseFunction
	_services      LunaServicesMapList
	_upgrader      *websocket.Upgrader
	_mu            sync.Mutex
}

// Registriert ein neues Service Objekt
func (obj *LunaSockets) RegisterService(service_object interface{}) error {
	// Es wird geprüft ob das Service Objekt zulässig ist
	if !validateServiceObject(service_object) {
		return fmt.Errorf("invalid serive object has no luna socket functions")
	}

	// Der Name des Dienstes wird abgerufen
	ptname := getObjectTypeName(service_object)

	// Sollte der Name Leer sein, wird der Vorgang abgebrochen
	if len(ptname) < 2 {
		return fmt.Errorf("invalid service canot register")
	}

	// Der Dienst wird hinzugefügt
	obj._services[ptname] = service_object

	// Der Vorgang wurde fehlerfrei durchgeführt
	return nil
}

// Diese Funktion wird ausgeführt um eine Serverseitige Verbindung zu Upgraden und eine LunaSocketSession Objekt zurückzugeben
func (obj *LunaSockets) UpgradeHTTPToLunaWebSocket(w http.ResponseWriter, r *http.Request) (LunaServerSession, error) {
	// upgrade the HTTP connection to a WebSocket connection
	ws, err := obj._upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Fatal("upgrade error:", err)
	}

	// Das Session Objekt wird erzeugt
	session_pbj := LunaSocketSession{_master: obj, _ws_conn: ws, _connected: true, _header: &r.Header}

	// Das Serverseitige Sitzungsobjekt wird erzeugt
	server_obj := LunaServerSession{Session: session_pbj, _mother: obj}

	// Die Sitzung wird zurückgegeben
	return server_obj, nil
}

// Diese Funktion wird auf der Clientseite verwendet
func (obj *LunaSockets) ClientServeWrappWS(conn *websocket.Conn, header *http.Header) (LunaSocketSession, error) {
	// Das Sitzungsobjekt wird erzeugt
	session_pbj := new(LunaSocketSession)
	session_pbj._master = obj
	session_pbj._ws_conn = conn
	session_pbj._connected = true
	session_pbj._header = header

	// Der WS_Connection Wrapper wird gestartet
	go func() {
		if err := obj._wrappWS(session_pbj); err != nil {
			fmt.Println(err)
		}
	}()

	// Die Daten werden zurückgegeben
	return *session_pbj, nil
}

// Diese Funktion gibt an ob es sich um eine zulässige Service Funktion handelt
func (obj *LunaSockets) isValidateServiceFunctionAndGetServiceObject(name string) (bool, interface{}) {
	// Es wird geprüft ob der Service Name korrekt ist
	if !validateFunctionCall(name) {
		return false, nil
	}

	// Der Name wird gesplitet
	splited_names := strings.Split(name, ".")

	// Es wird geprüft ob ein Passender Dienst verfügbar ist
	resolved, ok := obj._services[splited_names[0]]
	if !ok {
		return false, nil
	}

	// Es wird geprüft ob der Dienst die geforderte Funktion hat
	if !hasServiceAFunction(splited_names[1], resolved) {
		return false, nil
	}

	// Die Daten werden zurückgegebn
	return true, resolved
}

// Erstellt das neue Objekt
func NewLunaSocket() *LunaSockets {
	new_obj := new(LunaSockets)
	new_obj._services = make(LunaServicesMapList)
	new_obj._rpc_sessions = make(map[string]LunaRpcResponseFunction)
	new_obj._ping_sessions = make(map[string]LunaPingResponseFunction)
	new_obj._upgrader = &websocket.Upgrader{ReadBufferSize: 1024, WriteBufferSize: 1024}
	return new_obj
}
