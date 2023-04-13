package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"time"

	apiserver "github.com/fluffelpuff/HyperDirectory/apiserver"
	db "github.com/fluffelpuff/HyperDirectory/database"
)

func main() {
	// Die Datenbank wird geladen
	local_priv_key := ""
	db, err := db.CreateNewSQLiteBasedDatabase("/Volumes/Daten/test.db", &local_priv_key)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Lade Root-CA-Zertifikate
	rootCAs := x509.NewCertPool()
	pem, err := os.ReadFile("/Users/fluffelbuff/Desktop/DGPRootCA.crt")
	if err != nil {
		log.Fatalf("Fehler beim Lesen der Root-CA-Zertifikate: %v", err)
	}
	if !rootCAs.AppendCertsFromPEM(pem) {
		log.Fatalf("Fehler beim Parsen der Root-CA-Zertifikate")
	}

	// Der RPC Server wird gestartet
	cert_file, key_file := "/Users/fluffelbuff/Desktop/test.com.crt", "/Users/fluffelbuff/Desktop/test.com.pem"
	rpc_server, err := apiserver.CreateNewRPCServer(db, 9001, nil, &cert_file, &key_file, rootCAs)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Die Schleife wird solange ausgeführt, bis der RPC Server beendet wurde
	for rpc_server.IsRunning() {
		time.Sleep(1 * time.Millisecond)
	}
}
