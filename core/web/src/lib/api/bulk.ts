import type { DescMessage, DescMethodUnary, MessageInitShape } from '@bufbuild/protobuf';
import { ConnectError } from '@connectrpc/connect';
import { callUnaryMethod } from '@connectrpc/connect-query-core';
import { createMutation } from '@tanstack/svelte-query';
import { toast } from 'svelte-sonner';
import { useTransport } from '#lib/query/index.js';
import { formatConnectError } from './error-formatter';

export const plural = (n: number, noun: string, many = `${noun}s`) =>
	`${n} ${n === 1 ? noun : many}`;

type Input<I extends DescMessage> = Omit<MessageInitShape<I>, '$typeName'>;

// A grant on a big tag is hundreds of calls, a few at a time stays clear of the rate limit.
const PARALLEL = 6;

async function settle<T, R>(
	items: T[],
	run: (item: T) => Promise<R>
): Promise<PromiseSettledResult<R>[]> {
	const results: PromiseSettledResult<R>[] = [];
	let next = 0;
	const worker = async () => {
		while (next < items.length) {
			const i = next++;
			try {
				results[i] = { status: 'fulfilled', value: await run(items[i]) };
			} catch (reason) {
				results[i] = { status: 'rejected', reason };
			}
		}
	};
	await Promise.all(Array.from({ length: Math.min(PARALLEL, items.length) }, worker));
	return results;
}

// useBulkMutation runs one RPC per item as a single mutation, so a bulk action gives one toast and one invalidation.
export function useBulkMutation<I extends DescMessage, O extends DescMessage>(
	method: DescMethodUnary<I, O>,
	successMessage: (count: number) => string,
	transform: (input: Input<I>) => Input<I> = (input) => input
) {
	const transport = useTransport();

	return createMutation(() => ({
		mutationFn: async (inputs: Input<I>[]) => {
			const results = await settle(inputs, (input) =>
				callUnaryMethod(transport, method, transform(input) as MessageInitShape<I>)
			);
			const failures = results.flatMap((r) => (r.status === 'rejected' ? [r.reason] : []));
			if (failures.length === inputs.length) throw failures[0];
			return { ok: inputs.length - failures.length, failures };
		},
		onSuccess: ({ ok, failures }) => {
			toast.success(successMessage(ok));
			if (failures.length === 0) return;
			const first = ConnectError.from(failures[0]);
			toast.error(`${failures.length} of ${ok + failures.length} failed`, {
				description: formatConnectError(first).description ?? first.rawMessage
			});
		}
	}));
}
