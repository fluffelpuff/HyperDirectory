package lunasockets

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/mitchellh/mapstructure"
)

// Verhindert das ein Panic das Programm abstürzen lässt
func _panicHandler() {
	if r := recover(); r != nil {
		fmt.Println("Recovered from panic:", r)
	}
}

// Gibt an ob es sich um eine Zulässige Service Funtion handelt
func validateFunction(method reflect.Value) bool {
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

// Ruft eine Spizielle Service Funktion auf
func callServiceFunction(request *Request, service interface{}, methode_name string, args []interface{}) (*interface{}, error) {
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

	// Überprüfen Sie, ob die Methode gefunden wurde
	if !method.IsValid() {
		return nil, fmt.Errorf(fmt.Sprintf("MethodError: '%s' not found", methode_name))
	}

	// Es wird geprüft ob die Funktion zulässig ist und die benötigten Datentypen besitzt
	if !validateFunction(method) {
		return nil, fmt.Errorf("unknown method")
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

			// Die Daten werden Dekodiert
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

	// Speichert das Ergebniss ab
	var result []reflect.Value

	// Diese Funktion verhindet den Absturz des Programmes
	defer _panicHandler()

	// Ruft die eigenliche Funktion auf
	result = method.Call(reflectArgs)

	// Es wird geprüft ob sich mindestens 2 Einträge in den Results befinden
	if len(result) != 2 {
		return nil, fmt.Errorf(fmt.Sprintf("internal error by run function: %s", methode_name))
	}

	// Es wird geprüft ob ein Fehler aufgetreten ist
	if err, ok := result[1].Interface().(error); ok {
		return nil, err
	}

	// Der Rückgabewerte wird ermittelt
	reutn_value := result[0].Elem().Interface()

	// Die Daten werden zurückgegeben
	return &reutn_value, nil
}

// Wird verwendet um zu ermitteln ob es sich um einen zulässigen Funktionsaufruf handelt, wenn ja wird der Dienstname sowie der Funktionsname zurückgegen
func validateFunctionCall(value string) bool {
	if len(value) < 2 {
		return false
	}

	splited := strings.Split(value, ".")
	return len(splited) == 2
}

// Wird verwendet um zu ermitteln ob es sich bei einem Object um ein zulässigen Dienst handelt
func validateServiceObject(obj interface{}) bool {
	objectValue := reflect.ValueOf(obj)
	objectType := objectValue.Type()

	total := 0
	for i := 0; i < objectType.NumMethod(); i++ {
		if validateFunction(objectValue.Method(i)) {
			total++
			continue
		}
	}

	return total > 0
}

// Wird verwendet um den Typen der Variable zu ermitteln
func getObjectTypeName(obj interface{}) string {
	t := reflect.TypeOf(obj)
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t.Name()
}

// Gibt an ob die ein Dienst eine Gewisse Funktion hat
func hasServiceAFunction(fname string, service interface{}) bool {
	val := reflect.ValueOf(service)
	typ := val.Type()

	for i := 0; i < val.NumMethod(); i++ {
		methodName := typ.Method(i).Name
		if methodName == fname {
			return true
		}
	}

	return true
}

// Splitet den Namen ung gibt nur den Funktionsnamen zurück
func getFunctionNameOfCall(fname string) string {
	if !validateFunctionCall(fname) {
		return ""
	}
	splited := strings.Split(fname, ".")
	return splited[1]
}
