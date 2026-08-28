package hd

func DerivePath(seed []byte, path string) (*PrivateKey, error) {
	indices, err := ParsePath(path)
	if err != nil {
		return nil, err
	}

	key, err := NewMasterKey(seed)
	if err != nil {
		return nil, err
	}

	for _, i := range indices {
		key, err = key.Child(i)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}
