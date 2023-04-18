package lunasockets

import "net/http"

type FirstCheck struct {
	Id   string
	Type string
}

type RpcRequest struct {
	ProxyPass *http.Header  `json:"proxypass"`
	Params    []interface{} `json:"params"`
	JSONRPC   string        `json:"jsonrpc"`
	Method    string        `json:"method"`
	ID        int           `json:"id"`
}

type RpcResponse struct {
	Error  *string
	Result interface{}
}

type IoFlowPackage struct {
	Id   string
	Type string
	Body string
}

type HeaderData struct {
}

type TestObject struct {
	Value string
}

type TestStruct struct {
	Value string
}

type Request struct {
	Header        *http.Header
	OutPassedArgs []interface{}
}

type LunaRpcResponseFunction func(response RpcResponse)
type LunaPingResponseFunction func()
type LunaServicesMapList map[string]interface{}
