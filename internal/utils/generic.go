package utils

func IfNil[T any](val *T, defaultVal T) *T {
	if val == nil {
		return &defaultVal
	}
	return val
}
