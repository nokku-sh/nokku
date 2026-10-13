import { create } from '@bufbuild/protobuf';
import { RecordingService } from '#lib/gen/nokku/v1/recordings_pb.js';
import { useMutation, useQuery } from '#lib/query/index.js';
import { authTransport } from './client';
import { toast } from 'svelte-sonner';
import { MAX_PAGE_SIZE } from '#lib/config.js';
import { plural, useBulkMutation } from './bulk';

export type RecordingChunkHandler = (chunk: Uint8Array) => void;
export type RecordingMeta = { recordingId: string; username: string; principal: string };

export const recordings = {
	list: (
		opts?: () => {
			limit?: number;
			offset?: number;
			daemonId?: string;
			username?: string;
			subjectId?: string;
		}
	) =>
		useQuery(RecordingService.method.listRecordings, () => ({
			limit: MAX_PAGE_SIZE,
			offset: 0,
			...opts?.()
		})),

	delete: () =>
		useMutation(RecordingService.method.deleteRecording, {
			onSuccess: () => toast.success('Recording deleted')
		}),
	deleteMany: () =>
		useBulkMutation(
			RecordingService.method.deleteRecording,
			(n) => `${plural(n, 'recording')} deleted`
		),

	// Direct stream (connect-query has no server-stream support).
	stream: async (
		recordingId: string,
		onMeta: (meta: RecordingMeta) => void,
		onChunk: RecordingChunkHandler,
		signal?: AbortSignal
	): Promise<void> => {
		const input = create(RecordingService.method.getRecording.input, {
			recordingId
		});
		async function* single() {
			yield input;
		}
		const response = await authTransport.stream(
			RecordingService.method.getRecording,
			signal,
			undefined,
			undefined,
			single()
		);
		for await (const msg of response.message) {
			switch (msg.msg.case) {
				case 'meta':
					onMeta({
						recordingId: msg.msg.value.recordingId,
						username: msg.msg.value.username,
						principal: msg.msg.value.principal
					});
					break;
				case 'chunk':
					onChunk(msg.msg.value);
					break;
			}
		}
	}
};
