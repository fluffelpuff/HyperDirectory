package lunasockets

type LunaServerSession struct {
	Session LunaSocketSession
	_mother *LunaSockets
}

// Wird auf einer Serversitzung verwendet um Daten zu empfangen
func (obj *LunaServerSession) Serve() error {
	obj.Session._connected = true
	reval := obj._mother._wrappWS(obj.Session._ws_conn)
	obj.Session._connected = false
	return reval
}
