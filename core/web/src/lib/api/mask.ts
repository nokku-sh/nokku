import {
	isFieldSet,
	type DescField,
	type DescMessage,
	type DescMethodUnary,
	type MessageInitShape
} from '@bufbuild/protobuf';
import { useMutation, type UseMutationOptions } from '#lib/query/index.js';

type Input<I extends DescMessage> = Omit<MessageInitShape<I>, '$typeName'>;

// withMask names every field an update sets in its update_mask, so the server changes exactly those and keeps the
// rest. A plain empty list counts, it clears. Our own messages are named field by field, a Duration as a whole.
export function withMask<I extends DescMessage>(schema: I) {
	return (input: Input<I>): Input<I> =>
		({ ...input, updateMask: { paths: maskPaths(schema, input, '') } }) as Input<I>;
}

// usePatch is useMutation for an update RPC, the mask comes from what the input sets.
export function usePatch<I extends DescMessage, O extends DescMessage>(
	method: DescMethodUnary<I, O>,
	options: Omit<UseMutationOptions<I, O>, 'transform'> = {}
) {
	return useMutation(method, { ...options, transform: withMask(method.input) });
}

function maskPaths(desc: DescMessage, value: object, prefix: string): string[] {
	const message = '$typeName' in value;
	return desc.fields.flatMap((field) => {
		if (prefix === '' && (field.name === 'id' || field.name === 'update_mask')) return [];
		const v = (value as Record<string, unknown>)[field.localName];
		const set = message ? isFieldSet(value as never, field) : v !== undefined;
		if (!set) return [];
		const sub = ownMessage(field);
		if (sub) return maskPaths(sub, v as object, `${prefix}${field.name}.`);
		return [prefix + field.name];
	});
}

// ownMessage is the schema of a field holding one of our own messages, which masks and drafts split field by field.
export function ownMessage(field: DescField): DescMessage | undefined {
	return field.fieldKind === 'message' && field.message.typeName.startsWith('nokku.v1.')
		? field.message
		: undefined;
}
