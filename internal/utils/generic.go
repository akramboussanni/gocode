package utils

import "reflect"

func IfNil[T any](val *T, defaultVal T) *T {
	if val == nil {
		return &defaultVal
	}
	return val
}

func StripUnsafeFields[T any](ptr *T) {
	v := reflect.ValueOf(ptr)
	if v.Kind() != reflect.Ptr || v.Elem().Kind() != reflect.Struct {
		panic("StripUnsafeFields requires pointer to struct")
	}
	v = v.Elem()
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.Tag.Get("safe") != "true" {
			fv := v.Field(i)
			if fv.CanSet() {
				fv.Set(reflect.Zero(field.Type))
			}
		}
	}
}
