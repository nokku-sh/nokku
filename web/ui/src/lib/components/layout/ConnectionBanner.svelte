<script lang="ts">
	import { queryClient } from '#lib/api/client.js';
	import { connection } from '#lib/api/connection.svelte.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { formatTs } from '#lib/utils.js';
	import { timestampFromMs } from '@bufbuild/protobuf/wkt';
	import { CloudOff, WifiOff } from '@lucide/svelte';
	import { online } from 'svelte/reactivity/window';

	// The heartbeat in the app layout keeps trying, this is for the impatient.
	const retry = () => queryClient.invalidateQueries();
</script>

{#if online.current === false}
	<div
		class="flex shrink-0 items-center justify-center gap-2 border-b bg-warning/10 px-4 py-1.5 text-sm text-warning"
		role="status"
	>
		<WifiOff class="size-4 shrink-0" />
		You are offline. This page shows what it loaded before
	</div>
{:else if connection.lostAt}
	<div
		class="flex shrink-0 flex-wrap items-center justify-center gap-x-2 gap-y-1 border-b bg-warning/10 px-4 py-1.5 text-sm text-warning"
		role="status"
	>
		<CloudOff class="size-4 shrink-0" />
		<span>
			Can't reach the control plane since {formatTs(timestampFromMs(connection.lostAt), 'time')}.
			SSH with a valid certificate keeps working
		</span>
		<Button variant="outline" size="xs" onclick={retry}>Retry now</Button>
	</div>
{/if}
