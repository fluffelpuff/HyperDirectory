package lunasockets

import (
	"encoding/json"
	"fmt"
	"net/rpc"
	"reflect"
)

type RpcRequestCodec struct {
	closed  bool
	data    RpcRequest
	resolve interface{}
}

func (c *RpcRequestCodec) ReadRequestHeader(r *rpc.Request) error {
	r.ServiceMethod = c.data.Method
	r.Seq = uint64(c.data.ID)
	return nil
}

func (c *RpcRequestCodec) ReadRequestBody(x interface{}) error {
	// Die Daten werden in Bytes umgewandelt
	un, err := json.Marshal(c.data)
	if err != nil {
		return err
	}

	// Die Bytes werden eingelesen und zurückgegebn
	return json.Unmarshal(un, &x)
}

func (c *RpcRequestCodec) WriteResponse(r *rpc.Response, x interface{}) error {
	if x == nil {
		return fmt.Errorf("")
	}

	// Get the reflect value of x
	val := reflect.ValueOf(x)

	// Check if x is a pointer
	if val.Kind() == reflect.Ptr {
		// Dereference the pointer
		val = val.Elem()
	}

	// Print the value
	c.resolve = val.Interface()

	// Der Vorgang wurde erfolgreich beendet
	return nil
}

func (c *RpcRequestCodec) Close() error {
	c.closed = true
	return nil
}

func (c *RpcRequestCodec) GetResponse() (interface{}, error) {
	return c.resolve, nil
}
