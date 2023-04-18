package lunasockets

type FirstCheck struct {
	Id   string
	Type string
}

type RpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

type RpcResponse struct {
	Error  error
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
}

type LunaRpcResponseFunction func(response RpcResponse)
type LunaPingResponseFunction func()
type LunaServicesMapList map[string]interface{}