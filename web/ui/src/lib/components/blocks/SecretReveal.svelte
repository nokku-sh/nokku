<script lang="ts">
	import type { Snippet } from 'svelte';
	import * as Alert from '$lib/components/ui/alert';
	import * as Field from '$lib/components/ui/field';
	import { InputGroupVariants } from '$lib/components/ui/input-group';
	import { KeyRound } from '@lucide/svelte';

	interface Props {
		/** Each value gets its own copy field. */
		values?: { label?: string; value: string }[];
		note?: string;
		/** Custom reveal content, rendered after the values. */
		children?: Snippet;
	}

	let { values = [], note = 'Copy it now, it is only shown once.', children }: Props = $props();
</script>

<div class="flex flex-col gap-3">
	<Alert.Root variant="warning">
		<KeyRound />
		<Alert.Title>Shown once</Alert.Title>
		<Alert.Description>{note}</Alert.Description>
	</Alert.Root>
	{#each values as v, i (i)}
		<Field.Field>
			{#if v.label}<Field.Label>{v.label}</Field.Label>{/if}
			<InputGroupVariants variant="copy-input" value={v.value} readonly class="font-mono" />
		</Field.Field>
	{/each}
	{@render children?.()}
</div>
