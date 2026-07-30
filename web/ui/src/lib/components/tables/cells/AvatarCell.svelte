<script lang="ts">
	import Avatar, { type Variant } from '$lib/components/utils/Avatar.svelte';

	type Props = {
		id: string;
		name: string;
		variant?: Variant;
		description?: string;
	};
	let { id, name, variant, description, ...restProps }: Props = $props();
</script>

<div class="flex items-center gap-3" {...restProps}>
	<Avatar {id} {variant} class="size-8" />
	<div class="flex flex-col space-y-0.5">
		<span class="truncate text-sm leading-none font-medium" title={name}>{name}</span>
		{#if description}
			<span class="truncate text-xs text-muted-foreground" title={description}>
				{description}
			</span>
		{/if}
	</div>
</div>
