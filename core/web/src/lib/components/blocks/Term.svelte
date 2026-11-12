<script lang="ts">
	import type { Snippet } from 'svelte';
	import * as HoverCard from '#lib/components/ui/hover-card/index.js';
	import { glossary, type TermName } from '#lib/glossary.js';
	import { CircleQuestionMark } from '@lucide/svelte';
	import CopyCommand from './CopyCommand.svelte';

	interface Props {
		name: TermName;
		/** The word as the sentence writes it. Defaults to the name. */
		children?: Snippet;
	}

	let { name, children }: Props = $props();

	const term = $derived(glossary[name]);
</script>

<!-- A word explained where it is used, so the page stays short and a newcomer is one hover from the meaning. -->
<HoverCard.Root openDelay={150}>
	<HoverCard.Trigger>
		{#snippet child({ props })}
			<button
				{...props}
				type="button"
				class="inline-flex cursor-help items-center gap-1 rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-ring"
			>
				{#if children}{@render children()}{:else}{name}{/if}
				<CircleQuestionMark class="size-3 text-muted-foreground" aria-hidden="true" />
			</button>
		{/snippet}
	</HoverCard.Trigger>
	<HoverCard.Content class="flex w-80 flex-col gap-2 p-3 font-normal">
		<p class="spec-label">{term.title}</p>
		<p>{term.text}</p>
		{#if term.example}
			<CopyCommand command={term.example} class="self-start" />
		{/if}
	</HoverCard.Content>
</HoverCard.Root>
