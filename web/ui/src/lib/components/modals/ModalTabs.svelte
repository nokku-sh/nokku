<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { LucideIcon } from '@lucide/svelte';
	import * as Tabs from '$lib/components/ui/tabs';

	export interface ModalTab {
		value: string;
		label: string;
		icon?: LucideIcon;
	}

	interface Props {
		tabs: ModalTab[];
		children?: Snippet;
	}

	let { tabs, children }: Props = $props();
</script>

<Tabs.Root class="w-full">
	<Tabs.List class="mb-4 grid w-full" style="grid-template-columns: repeat({tabs.length}, 1fr)">
		{#each tabs as tab (tab.value)}
			{@const TabIcon = tab.icon}
			<Tabs.Trigger value={tab.value}>
				{#if TabIcon}
					<TabIcon />
				{/if}
				{tab.label}
			</Tabs.Trigger>
		{/each}
	</Tabs.List>
	{@render children?.()}
</Tabs.Root>
