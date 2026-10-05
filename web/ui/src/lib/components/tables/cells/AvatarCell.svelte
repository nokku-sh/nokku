<script lang="ts">
	import Avatar from '#lib/components/blocks/Avatar.svelte';

	type Props = {
		id: string;
		name: string;
		description?: string;
	};
	let { id, name, description, ...restProps }: Props = $props();
</script>

<div class="flex items-center gap-3" {...restProps}>
	<Avatar {id} class="size-8" />
	<div class="flex flex-col">
		<span class="truncate text-sm font-medium" title={name}>{name}</span>
		{#if description}
			<span class="truncate text-xs text-muted-foreground" title={description}>
				{description}
			</span>
		{/if}
	</div>
</div>
