<script lang="ts">
	import type { Snippet } from 'svelte';
	import * as Alert from '#lib/components/ext/alert/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import InputGroupVariants from '#lib/components/blocks/InputGroupVariants.svelte';
	import { KeyRound } from '@lucide/svelte';

	interface Props {
		/** Each value gets its own copy field. */
		values?: { label?: string; value: string }[];
		note?: string;
		/** Custom reveal content, rendered after the values. */
		children?: Snippet;
	}

	let { values = [], note = 'Copy it now, it is only shown once.', children }: Props = $props();

	const uid = $props.id();
</script>

<div class="flex flex-col gap-3">
	<Alert.Root variant="warning">
		<KeyRound />
		<Alert.Title>Shown once</Alert.Title>
		<Alert.Description>{note}</Alert.Description>
	</Alert.Root>
	{#each values as v, i (i)}
		<Field.Field>
			{#if v.label}<Field.Label for={`${uid}-${i}`}>{v.label}</Field.Label>{/if}
			<InputGroupVariants
				variant="copy-input"
				value={v.value}
				readonly
				class="font-mono"
				copyLabel={v.label}
				inputProps={{ id: `${uid}-${i}` }}
			/>
		</Field.Field>
	{/each}
	{@render children?.()}
</div>
