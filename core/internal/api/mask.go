package api

import (
	"strings"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// maskTree is an update mask as a tree, one level per dotted name.
type maskTree map[string]maskTree

type maskedRequest interface {
	proto.Message
	GetUpdateMask() *fieldmaskpb.FieldMask
}

// applyMask clears every field the mask leaves out, so handlers can check
// presence. A named field with presence must be set, or it would store a value
// no rule checked. For lists, which have no presence, use named.
func applyMask(req proto.Message, mask *fieldmaskpb.FieldMask) (named func(field string) bool, err error) {
	tree := maskTree{}
	for _, path := range mask.GetPaths() {
		node := tree
		for name := range strings.SplitSeq(path, ".") {
			if node[name] == nil {
				node[name] = maskTree{}
			}
			node = node[name]
		}
	}
	if err := prune(req.ProtoReflect(), tree, ""); err != nil {
		return nil, err
	}
	return func(field string) bool { _, ok := tree[field]; return ok }, nil
}

// The queries keep the stored list for nil, so a named list is never nil.
func maskedList(named bool, v []string) []string {
	if !named {
		return nil
	}
	return append([]string{}, v...)
}

func prune(m protoreflect.Message, tree maskTree, prefix string) error {
	fields := m.Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		name := string(fd.Name())
		if prefix == "" && (name == "id" || name == "update_mask") {
			continue
		}
		sub, named := tree[name]
		switch {
		case !named:
			m.Clear(fd)
		case fd.HasPresence() && !m.Has(fd):
			return connect.NewError(
				connect.CodeInvalidArgument,
				"update_mask names "+prefix+name+", so the request has to set it",
			)
		case len(sub) > 0:
			// Only our messages have nameable parts, a Duration is set whole.
			if !ownMessage(fd) {
				return connect.NewError(
					connect.CodeInvalidArgument,
					"update_mask names part of "+prefix+name+", name it whole",
				)
			}
			if err := prune(m.Mutable(fd).Message(), sub, prefix+name+"."); err != nil {
				return err
			}
		}
	}
	return nil
}

// mergeSet replaces anything but our own messages whole, so a zero Duration
// turns a timeout off where proto.Merge would keep the old one.
func mergeSet(dst, src protoreflect.Message) {
	src.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if ownMessage(fd) {
			mergeSet(dst.Mutable(fd).Message(), v.Message())
			return true
		}
		dst.Set(fd, v)
		return true
	})
}

func ownMessage(fd protoreflect.FieldDescriptor) bool {
	return fd.Message() != nil && !fd.IsList() && !fd.IsMap() && fd.Message().ParentFile().Package() == "nokku.v1"
}
