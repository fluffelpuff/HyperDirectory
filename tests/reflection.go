package main

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/mitchellh/mapstructure"
)

type MyService struct{}

type TestStruct struct {
	Name string
}

type Response struct{}

type Request struct {
}

type RpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

func (s *MyService) DoAnotherThing(req *Request, tst *TestStruct) (*string, error) {
	a := "abcdefg"
	fmt.Println("TEST_FNC")
	return &a, nil
}

func ValidateFunction(method reflect.Value) bool {
	numIn := method.Type().NumIn()
	if numIn != 2 {
		return false
	}
	for i := 0; i < numIn; i++ {
		paramType := method.Type().In(i)
		if paramType.Kind() != reflect.Ptr {
			return false
		}
	}
	numOut := method.Type().NumOut()
	if numOut != 2 {
		return false
	}
	returnType := method.Type().Out(0)
	if returnType.Kind() != reflect.Ptr {
		return false
	}
	if method.Type().Out(1) != reflect.TypeOf((*error)(nil)).Elem() {
		return false
	}
	return true
}

func CallServiceFunction(request *Request, service interface{}, methode_name string, args []interface{}) (*interface{}, error) {
	// Definieren Sie den Methodennamen und die Argumente als Slice von reflect.Value
	reflectArgs := make([]reflect.Value, 0)

	// Erstellen Sie einen Pointer auf das Argument
	arg := reflect.New(reflect.TypeOf(*request))

	// Fügen Sie den Pointer zu den Argumenten hinzu
	reflectArgs = append(reflectArgs, arg)

	// Holen Sie sich den Typ des Service-Objekts
	t := reflect.TypeOf(service)

	// Überprüfen Sie, ob der Typ ein Pointer zu einem Struct ist
	if t.Kind() != reflect.Ptr || t.Elem().Kind() != reflect.Struct {
		fmt.Println("TypeError: 'service' ist kein Pointer auf ein Struct")
		return nil, fmt.Errorf("")
	}

	// Holen Sie sich den Wert des Service-Objekts
	v := reflect.ValueOf(service)

	// Holen Sie sich die Methode anhand des Namens
	method := v.MethodByName(methode_name)

	// Es wird geprüft ob die Funktion zulässig ist und die benötigten Datentypen besitzt
	if !ValidateFunction(method) {
		return nil, fmt.Errorf("unknown method")
	}

	// Überprüfen Sie, ob die Methode gefunden wurde
	if !method.IsValid() {
		fmt.Printf("MethodError: '%s' Methode wurde nicht gefunden\n", methode_name)
		return nil, fmt.Errorf("E")
	}

	// Die Parameter des Benutzers werden abgearbeitet
	for i, v := range args {
		// Überprüfen, ob das Argument ein Struct ist
		if reflect.TypeOf(v).Kind() == reflect.Struct {
			// Erstellen Sie einen Pointer auf eine neue Instanz des Struct-Typs
			structType := reflect.TypeOf(v)
			structArg := reflect.New(structType).Elem()

			// Füllen Sie die Felder des Structs mit den Werten aus dem übergebenen Struct
			for j := 0; j < structType.NumField(); j++ {
				structArg.Field(j).Set(reflect.ValueOf(v).Field(j))
			}

			// Erstellen Sie einen Pointer auf das Struct
			arg := structArg.Addr()

			// Fügen Sie den Pointer zu den Argumenten hinzu
			reflectArgs = append(reflectArgs, arg)
		} else if m, ok := v.(map[string]interface{}); ok {
			// Der Datentyp wird ermittelt
			dest := reflect.New(method.Type().In(i + 1).Elem()).Interface()
			err := mapstructure.Decode(m, &dest)
			if err != nil {
				return nil, err
			}
			if err != nil {
				return nil, err
			}

			// Erstellen Sie einen Pointer auf das Struct
			argValue := reflect.ValueOf(dest)
			argPtr := reflect.New(argValue.Type())
			argPtr.Elem().Set(argValue)

			// Fügen Sie den Pointer zu den Argumenten hinzu
			reflectArgs = append(reflectArgs, argPtr.Elem())
		} else {
			// Erstellen Sie einen Pointer auf das Argument
			arg := reflect.New(reflect.TypeOf(v))
			arg.Elem().Set(reflect.ValueOf(v))

			// Fügen Sie den Pointer zu den Argumenten hinzu
			reflectArgs = append(reflectArgs, arg)
		}
	}

	// Rufen Sie die Methode auf und übergeben Sie die Argumente
	var result []reflect.Value
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered from panic:", r)
		}
	}()
	result = method.Call(reflectArgs)

	// Es wird geprüft ob ein Fehler aufgetreten ist
	if err, ok := result[1].Interface().(error); ok {
		return nil, err
	}

	// Der Rückgabewerte wird ermittelt
	reutn_value := result[0].Elem().Interface()

	// Die Daten werden zurückgegeben
	return &reutn_value, nil
}

func main() {
	service := &MyService{}
	args := []interface{}{TestStruct{Name: "test"}}

	// Konvertieren des Slice in JSON
	jsonData, err := json.Marshal(args)
	if err != nil {
		fmt.Println("Fehler beim Konvertieren in JSON:", err)
		return
	}
	fmt.Println(string(jsonData))

	var argsFromJSON []interface{}
	err = json.Unmarshal(jsonData, &argsFromJSON)
	if err != nil {
		fmt.Println("Fehler beim Konvertieren von JSON:", err)
		return
	}

	req := Request{}
	result, err := CallServiceFunction(&req, service, "DoAnotherThing", argsFromJSON)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(*result)
}
