<script lang="ts">
	import type { Timestamp } from '@bufbuild/protobuf/wkt';
	import { auditUTC } from '$lib/store.svelte';
	import { formatTs } from '$lib/utils';
	import { formatTime } from '$lib/components/audit/audit';

	let { ts }: { ts?: Timestamp } = $props();
</script>

<div class="flex flex-col whitespace-nowrap">
	<span class="font-mono text-xs tabular-nums">{formatTime(ts, auditUTC.current)}</span>
	<span class="text-xs text-muted-foreground">{formatTs(ts, 'relative')}</span>
</div>
