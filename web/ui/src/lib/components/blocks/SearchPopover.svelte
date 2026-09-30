<script lang="ts">
	import type { Snippet } from 'svelte';
	import * as Command from '$lib/components/ui/command';
	import * as Popover from '$lib/components/ui/popover';
	import { Spinner } from '$lib/components/ui/spinner';

	interface Props {
		open?: boolean;
		/** Raw input, callers debounce it into their queries. */
		query?: string;
		placeholder?: string;
		empty?: string;
		loading?: boolean;
		align?: 'start' | 'center' | 'end';
		trigger: Snippet<[Record<string, unknown>]>;
		/** Command groups and items. Filtering happens on the server. */
		children: Snippet;
	}

	let {
		open = $bindable(false),
		query = $bindable(''),
		placeholder = 'Search...',
		empty = 'Nothing found.',
		loading = false,
		align = 'start',
		trigger,
		children
	}: Props = $props();
</script>

<Popover.Root
	bind:open
	onOpenChange={(value) => {
		if (!value) query = '';
	}}
>
	<Popover.Trigger>
		{#snippet child({ props })}
			{@render trigger(props)}
		{/snippet}
	</Popover.Trigger>
	<Popover.Content class="w-72 p-0" {align}>
		<Command.Root shouldFilter={false}>
			<Command.Input bind:value={query} {placeholder} />
			<Command.List>
				{#if loading}
					<div class="flex justify-center py-6"><Spinner /></div>
				{:else}
					<Command.Empty>{empty}</Command.Empty>
				{/if}
				{@render children()}
			</Command.List>
		</Command.Root>
	</Popover.Content>
</Popover.Root>
