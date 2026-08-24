import { create } from '@bufbuild/protobuf';
import { RecordingService } from '$lib/gen/nokku/v1/recordings_pb';
import { useMutation, useQuery } from '$lib/query';
import { workspaceID } from '$lib/store.svelte';
import { authTransport } from './client';
import { toast } from 'svelte-sonner';

export type RecordingChunkHandler = (chunk: Uint8Array) => void;
export type RecordingMeta = { recordingId: string; username: string };

export const recordings = {
	// Queries
	list: () =>
		useQuery(
			RecordingService.method.listRecordings,
			() => ({
				workspaceId: workspaceID.current,
				limit: 100,
				offset: 0
			}),
			{
				enabled: !!workspaceID.current,
				refetchInterval: 30000
			}
		),

	// Mutations
	delete: () =>
		useMutation(RecordingService.method.deleteRecording, {
			onSuccess: () => toast.success('Recording deleted')
		}),

	// Direct stream (connect-query has no server-stream support).
	stream: async (
		recordingId: string,
		onMeta: (meta: RecordingMeta) => void,
		onChunk: RecordingChunkHandler,
		signal?: AbortSignal
	): Promise<void> => {
		const input = create(RecordingService.method.getRecording.input, {
			workspaceId: workspaceID.current,
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
						username: msg.msg.value.username
					});
					break;
				case 'chunk':
					onChunk(msg.msg.value);
					break;
			}
		}
	}
};
