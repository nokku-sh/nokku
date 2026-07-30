package billing

import "github.com/polarsource/polar-go/models/components"

func MergeMetadata(
	meta1 map[string]components.MetadataOutputType,
	meta2 map[string]components.MetadataOutputType,
) map[string]any {
	out := make(map[string]any, len(meta1)+len(meta2))

	for k, v := range meta1 {
		out[k] = serializeMetadataValue(v)
	}
	for k, v := range meta2 {
		out[k] = serializeMetadataValue(v)
	}
	return out
}

func serializeMetadataValue(v components.MetadataOutputType) any {
	if v.Integer != nil {
		return *v.Integer
	}
	if v.Number != nil {
		return *v.Number
	}
	if v.Str != nil {
		return *v.Str
	}
	if v.Boolean != nil {
		return *v.Boolean
	}
	return nil
}
