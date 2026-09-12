package signer

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func ParseTypedDataJSON(data []byte) (TypedData, error) {
	var typedData TypedData
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	err := dec.Decode(&typedData)
	if err != nil {
		return TypedData{}, err
	}
	if _, ok := typedData.Types[typedData.PrimaryType]; !ok {
		return TypedData{}, fmt.Errorf("primaryType %q not found in types", typedData.PrimaryType)
	}
	delete(typedData.Types, "EIP712Domain")

	return typedData, nil

}
