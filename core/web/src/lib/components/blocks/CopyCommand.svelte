<script lang="ts">
	import { cn } from '#lib/utils.js';
	import { SquareTerminal } from '@lucide/svelte';
	import CopyText from './CopyText.svelte';

	let { command, class: className }: { command: string; class?: string } = $props();
</script>

<!-- A command to run in a terminal, one click copies it. -->
<div
	class={cn('flex min-w-0 items-center gap-2 rounded-lg border bg-muted/40 px-3 py-1', className)}
>
	<SquareTerminal class="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
	<CopyText value={command} mono class="text-sm" />
</div>
