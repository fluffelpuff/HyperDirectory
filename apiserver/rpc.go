package apiserver

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"

	"github.com/fluffelpuff/HyperDirectory/base"
	db "github.com/fluffelpuff/HyperDirectory/database"
	lunasockets "github.com/fluffelpuff/LunaSockets"

	"github.com/divan/gorilla-xmlrpc/xml"
	"github.com/gorilla/mux"
	"github.com/gorilla/rpc"
	"github.com/gorilla/rpc/json"
)

// Stellt ein RPC Server Objekt dar
type RestAPIServer struct {
	Database   *db.Database
	NetListner *net.Listener
	isRunning  bool
}

type Request struct {
	Method string        `json:"method"`
	Params []interface{} `json:"params"`
}

type Response struct {
	Result interface{} `json:"result"`
	Error  interface{} `json:"error"`
}

// DEPRECATED: This function is deprecated and should not be used.
type RPC struct{}

// Gibt an ob der RPC Server ausgeführt wird
func (t *RestAPIServer) IsRunning() bool {
	return t.isRunning
}

// Wird verwendet um zu überprüfen ob der Directory Service User berechtig ist einen VOrgang durchzuführen,
// wenn ja wird ein Request Eintrag in der Datenbank erstellt und eine Live Request Session Process Objekt zurückgegeben
func VDSPAG_DB_ENTRY(t *db.Database, r *lunasockets.Request, function_name string) (*base.LiveRPCSessionProcess, error) {
	// Es wird geprüft ob die RPC Sitzungsdaten vorhanden sind
	if len(r.OutPassedArgs) < 1 {
		return nil, fmt.Errorf("internal error, no live session 1")
	}

	// Es wird geprüft ob es sich um eine LiveRPCSitzung handelt
	lrpcs, ok := r.OutPassedArgs[0].(*base.LiveRPCSession)
	if !ok {
		return nil, fmt.Errorf("internal error, no live session 2")
	}

	// Es wird ein neuer Request Eintrag in der Datenabnk erzeugt
	ok, result, err := t.ValidateDirectoryServiceUserPremissionAndStartProcess(lrpcs, r.Header, function_name, r.ProxyPass)
	if err != nil {
		return nil, err
	}

	// Sollte der Benutzer nicht berechtigt sein, wird der Vorgang abgebrochen
	if !ok {
		return nil, fmt.Errorf("user hasn't premission")
	}

	// Das Resuldat wird zurückgegeben
	return result, nil
}

// Wird verwendet um eine Metadaten Sitzung zu schlißen
func CloseSessionRequest(t *db.Database, request_session *base.RequestMetaDataSession, warning *string, errort error) {
	// Es wird eine Anfrage an die Datenbank gestellt um den Request zu schließen
	if err := t.CloseEntrySessionRequest(request_session, warning, errort); err != nil {
		fmt.Println("Unkown internal error: " + err.Error())
		return
	}

	fmt.Println("Request closed")
}

// Wird verwendet bevor eine Funktion aufgerufen wird
func _bevorMethodeCallEvent(db *db.Database, cert_fingerprint string) (bool, error) {
	return false, nil
}

// Wird aufgerufen nachdem eine Funtkion aufgerufen wurde
func _afterMethodeCallEvent(db *db.Database, cert_fingerprint string) (bool, error) {
	return false, nil
}

// Wird verwendet um eine LunaRPCWebsocket Sitzung aus einer HTTP Sitzung zu erstellen
func ServeUpgrageToLunaRPCWebsocket(hyper_rpc_server *lunasockets.LunaSockets, db *db.Database, w http.ResponseWriter, r *http.Request) {
	// Es wird geprüft ob die Zertifikate vorhanden
	if len(r.TLS.PeerCertificates) == 0 {
		log.Fatalln("no verification certificates available")
		return
	}

	// Extrahieren Sie den Fingerprint des Serverzertifikats
	fingerprint := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	hex_fingerprint := hex.EncodeToString(fingerprint[:])

	// Die Metadaten der Verbindung werden ermittelt
	connection, clen, content_type := r.Header.Get("Connection"), r.Header.Get("Content-Length"), r.Header.Get("Content-Type")
	user_agent, host, accept, encodings := r.Header.Get("User-Agent"), r.Header.Get("Host"), r.Header.Get("Accept"), r.Header.Get("Accept-Encoding")

	// Die IP-Adresse der Anfragendenseite wird ermittelt
	ip, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Fatalln("invalid port")
		return
	}
	netIP := net.ParseIP(ip)
	if netIP == nil {
		log.Fatalln("invalid ip-address")
		return
	}

	// Es wird eine Anfrage an die Datenbank gestellt um die Live Sitzung zu erstellen
	auth, session, err := db.ValidateDirectoryAPIUserAndGetLiveSession(hex_fingerprint, user_agent, host, accept, encodings, connection, clen, content_type, ip, port, nil)
	if err != nil {
		log.Fatalln("internal error:" + err.Error())
		return
	}

	// Es wird geprüft ob der Benutzer verifiziert wurde
	if !auth {
		log.Printf("not authorized %s user\n", hex_fingerprint)
		return
	}

	// Die Verbindung wird zu einer Luna Websocket Sitzung geupgradet
	server_sess, err := hyper_rpc_server.UpgradeHTTPToLunaWebSocket(w, r)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Die Sitzung wird zwischengspeichert
	server_sess.AddOutParameter(session)

	// Der Log text wird angezeigt
	log.Printf("new websocket connection accepted from %s\n", hex_fingerprint)

	// Die Verbindung wird Served
	if err := server_sess.Serve(); err != nil {
		if err := db.CloseDirectoryAPIUserLiveSession(session, err, nil); err != nil {
			log.Printf("Websocket connection closed %s with error %s\n", hex_fingerprint, err.Error())
			return
		} else {
			log.Printf("Websocket connection closed %s\n", hex_fingerprint)
			return
		}
	}

	// Die Aktuelle Sitzung wird in der Datenbank geschlossen
	if err := db.CloseDirectoryAPIUserLiveSession(session, nil, nil); err != nil {
		log.Printf("Websocket connection closed %s with error %s\n", hex_fingerprint, err.Error())
		return
	}

	// Der Log text wird angezeigt
	log.Printf("Websocket connection closed %s\n", hex_fingerprint)
}

// Erstellt einen neuen RPC Server
func CreateNewRPCServer(database *db.Database, rpc_port uint, fqdn *string, ssl_cert *string, ssl_priv_key *string, root_cas *x509.CertPool) (*RestAPIServer, error) {
	// Der RPC JSON Server wird erstellt
	json_rpc_server := rpc.NewServer()
	json_rpc_server.RegisterCodec(json.NewCodec(), "application/json")
	json_rpc_server.RegisterCodec(json.NewCodec(), "application/json;charset=UTF-8")
	json_rpc_server.RegisterService(&Session{Database: database}, "")

	// Der RPC XML Server wird erstellt
	xml_rpc_server := rpc.NewServer()
	xml_rpc_server.RegisterCodec(xml.NewCodec(), "application/xml")
	xml_rpc_server.RegisterService(&Session{Database: database}, "")

	// Der LunaSockets Socket wird erstellt
	hyper_rpc_server := lunasockets.NewLunaSocket()
	if err := hyper_rpc_server.RegisterService(&User{Database: database}); err != nil {
		return nil, fmt.Errorf("CreateNewRPCServer: " + err.Error())
	}

	// Der Webserver wird erstellt
	router := mux.NewRouter()

	// Es wird geprüft ob eine Domain angegeben wurde
	if fqdn != nil {
		router = router.Host(*fqdn).Headers("Connection", "Keep-Alive").Subrouter()
	}

	// Der JSON Endpunkt wird registriert
	router.Handle("/jsonrpc", json_rpc_server)

	// Der XML Endpunkt wird registriert
	router.Handle("/xmlrpc", xml_rpc_server)

	// Der WS Endpunkt wird registriert
	router.HandleFunc("/wsrpc", func(w http.ResponseWriter, r *http.Request) {
		ServeUpgrageToLunaRPCWebsocket(hyper_rpc_server, database, w, r)
	})

	// Das Rückgabeobjekt wird erzeugt
	return_obj := RestAPIServer{Database: database}
	return_obj.isRunning = true

	// Das Zertifikat wird geladen
	cert, err := tls.LoadX509KeyPair(*ssl_cert, *ssl_priv_key)
	if err != nil {
		log.Fatalf("Fehler beim Laden der Zertifikate: %v", err)
	}

	// Die Konfiguration wird erstellt
	tlsConfig := &tls.Config{
		ClientCAs:    root_cas,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		RootCAs:      root_cas,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Der Server wird erzeugt
	srv := &http.Server{
		Addr:      ":" + strconv.Itoa(int(rpc_port)),
		Handler:   router,
		TLSConfig: tlsConfig,
	}

	// Der Server wird gestartet
	go func() {
		err := srv.ListenAndServeTLS("", "")
		if err != nil {
			log.Fatal("ListenAndServeTLS error:", err)
		}
	}()

	// Das Objekt wird zurückgegeben
	fmt.Println("RPC server started")
	return &return_obj, nil
}
