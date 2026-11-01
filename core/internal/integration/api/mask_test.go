//go:build integration

package api_test

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// masked names every field req sets in update_mask, like the web app. A mask
// already set stays, for a case that names an empty list.
func masked[T proto.Message](req T) T {
	m := req.ProtoReflect()
	fd := m.Descriptor().Fields().ByName("update_mask")
	if !m.Has(fd) {
		m.Set(fd, protoreflect.ValueOfMessage((&fieldmaskpb.FieldMask{Paths: setPaths(m, "")}).ProtoReflect()))
	}
	return req
}

func setPaths(m protoreflect.Message, prefix string) []string {
	var paths []string
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		name := string(fd.Name())
		switch {
		case prefix == "" && (name == "id" || name == "update_mask"):
		case fd.Message() != nil && !fd.IsList() && !fd.IsMap() && fd.Message().ParentFile().Package() == "nokku.v1":
			paths = append(paths, setPaths(v.Message(), prefix+name+".")...)
		default:
			paths = append(paths, prefix+name)
		}
		return true
	})
	return paths
}
