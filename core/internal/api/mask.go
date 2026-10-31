package api

import (
	"strings"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// maskTree is an update mask as a tree, "config.record_sessions" is config, then record_sessions.
type maskTree map[string]maskTree

// maskedRequest is any update request, each carries an update_mask.
type maskedRequest interface {
	proto.Message
	GetUpdateMask() *fieldmaskpb.FieldMask
}

// applyMask clears every field of an update request its mask does not name, so a handler that checks presence
// changes exactly the named fields. A named field that tracks presence has to be sent, so naming one never stores
// a value no rule checked. Lists have no presence, named tells a handler whether to write one.
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

// maskedList is the list a query writes. The queries keep the stored list for nil, so a named one is never nil,
// even when empty.
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
			return newError(
				connect.CodeInvalidArgument,
				"update_mask names "+prefix+name+", so the request has to set it",
			)
		case len(sub) > 0:
			// Only our own messages have parts a mask may name. A Duration is set whole, like a list or a string.
			if !ownMessage(fd) {
				return newError(connect.CodeInvalidArgument, "update_mask names part of "+prefix+name+", name it whole")
			}
			if err := prune(m.Mutable(fd).Message(), sub, prefix+name+"."); err != nil {
				return err
			}
		}
	}
	return nil
}

// mergeSet copies every field src has onto dst. Our own messages merge field by field. Anything else, like a
// Duration, replaces the stored value whole, so a zero timeout turns it off where proto.Merge would keep the old.
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
