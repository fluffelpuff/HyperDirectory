package restapi

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

// Gibt an ob der RPC Server ausgeführt wird
func (t *RestAPIServer) IsRunning() bool {
	return t.isRunning
}

// Diese Funktion ließt die Header Proxy Daten ein
func readProxyHeaderData(origbasedata string) (*base.RequestMetaData, error) {
	return nil, nil
}

// Wird verwendet um die Logindaten des Services Users zu prüfen
func ValidateServiceAPIUser(t *db.Database, r *http.Request, function_name string, smeta_data base.RequestMetaDataSession) (bool, bool, *base.DirectoryServiceProcess, error) {
	// Es wird geprüft ob die Zertifikate vorhanden
	if len(r.TLS.PeerCertificates) == 0 {
		return false, false, nil, fmt.Errorf("ValidateServiceAPIUser: no cert")
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
		return false, false, nil, fmt.Errorf("ValidateServiceAPIUser: invalid source ip data")
	}
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return false, false, nil, fmt.Errorf("ValidateServiceAPIUser: invalid source ip data")
	}

	// Es wird eine Anfrage an die Datenbank gestellt um zu überprüfen ob der Benutzer exestiert und berechtigt ist für diese Aktion
	accepted, result, err := t.ValidateDirectoryAPIUserAndGetProcessId(hex_fingerprint, user_agent, host, accept, encodings, connection, clen, content_type, ip, port, function_name, smeta_data)
	if err != nil {
		return false, false, nil, fmt.Errorf("ValidateServiceAPIUser: " + err.Error())
	}

	// Es wird geprüft ob die Daten Akzeptiert wurden
	if !accepted {
		return false, false, nil, nil
	}

	// Es wird geprüft ob der Benutzer für die Aktuelle Funktion berechtigt ist
	if !result.IsAllowedFunction(function_name) {
		return true, false, result, nil
	}

	// Der Vorgang wurde erfolgreich durchgeführt
	return true, true, result, nil
}

// Erstellt ein neues Metadaten Objekt und schreibt dieses in eine Datenbank
func CreateNewSessionRequestEntryAndGet(t *db.Database, r *http.Request, function_name string) (*base.RequestMetaDataSession, error) {
	// Es wird geprüft ob ein Proxy Eintrag vorhanden ist
	proxy_data := r.Header.Get("Origin-Request-Proxy-Data")
	if len(proxy_data) > 0 {
		// Es versucht die Daten zu dekodieren
		decoded, err := readProxyHeaderData(proxy_data)
		if err != nil {
			return nil, fmt.Errorf("GetMetadataWithDbEnty: " + err.Error())
		}

		// Der Eintrag wird in der Datenbank erstellt
		result, err := t.OpenNewRequestEntryAndGetId(decoded, function_name, true)
		if err != nil {
			return nil, err
		}

		// Die Resultdaten werden zurückgegeben
		return result, nil
	}

	// Die IP-Adresse der Anfragendenseite wird ermittelt
	ip, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("GetMetadataWithDbEnty: invalid source ip data")
	}
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return nil, fmt.Errorf("GetMetadataWithDbEnty: invalid source ip data")
	}

	// Das Request Objekt wird erzeugt
	req_obj := base.RequestMetaData{
		SourcePort:    port,
		SourceIp:      ip,
		Connection:    r.Header.Get("Connection"),
		ContentLength: r.Header.Get("Content-Length"),
		ContentType:   r.Header.Get("Content-Type"),
		Encodings:     r.Header.Get("Accept-Encoding"),
		UserAgent:     r.Header.Get("User-Agent"),
		Domain:        r.Header.Get("Host"),
	}

	// Der Eintrag wird in der Datenbank erstellt
	result, err := t.OpenNewRequestEntryAndGetId(&req_obj, function_name, false)
	if err != nil {
		return nil, err
	}

	// Das Resuldat wird zurückgegeben
	return result, nil
}

// Wird verwendet um eine Metadaten Sitzung zu schlißen
func CloseSessionRequest(t *db.Database, r *http.Request, request_session *base.RequestMetaDataSession, warning *string, errort error) {
	// Es wird eine Anfrage an die Datenbank gestellt um den Request zu schließen
	if err := t.CloseEntrySessionRequest(request_session, warning, errort); err != nil {
		fmt.Println("Unkown internal error: " + err.Error())
		return
	}

	fmt.Println("Request closed")
}

// Erstellt einen neuen RPC Server
func CreateNewRPCServer(database *db.Database, rpc_port uint, fqdn *string, ssl_cert *string, ssl_priv_key *string, root_cas *x509.CertPool) (*RestAPIServer, error) {
	// Der RPC JSON Server wird erstellt
	json_rpc_server := rpc.NewServer()
	json_rpc_server.RegisterCodec(json.NewCodec(), "application/json")
	json_rpc_server.RegisterCodec(json.NewCodec(), "application/json;charset=UTF-8")
	json_rpc_server.RegisterService(&Session{Database: database}, "")
	json_rpc_server.RegisterService(&User{Database: database}, "")

	// Der RPC XML Server wird erstellt
	xml_rpc_server := rpc.NewServer()
	xml_rpc_server.RegisterCodec(xml.NewCodec(), "application/xml")
	xml_rpc_server.RegisterService(&Session{Database: database}, "")
	xml_rpc_server.RegisterService(&User{Database: database}, "")

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
