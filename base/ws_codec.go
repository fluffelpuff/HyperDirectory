package base

import (
	"github.com/gorilla/websocket"
)

// Verwaltet die Verbindung
type WSConnection struct {
	_wsconnection *websocket.Conn
}

func (t *WSConnection) GetRPCCodec() (*WSRPCCodec, error) {
	return &WSRPCCodec{_ws_conn: t}, nil
}

func (t *WSConnection) ReadRPC(p []byte) (n int, err error) {
	return 0, nil
}

func (t *WSConnection) WriteRPC(p []byte) (n int, err error) {
	err = t._wsconnection.WriteMessage(websocket.TextMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *WSConnection) Close() error {
	return nil
}

// Verwaltet das Clientside RPC
type WSRPCCodec struct {
	WS       *websocket.Conn
	_ws_conn *WSConnection
}

func (c *WSRPCCodec) Read(p []byte) (n int, err error) {
	_, r, err := c.WS.NextReader()
	if err != nil {
		return 0, err
	}
	return r.Read(p)
}

func (c *WSRPCCodec) Write(p []byte) (n int, err error) {
	err = c.WS.WriteMessage(websocket.TextMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *WSRPCCodec) Close() error {
	return c.WS.Close()
}
