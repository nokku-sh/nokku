<script lang="ts">
	import { roles as rolesApi } from '$lib/api/roles.svelte';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import * as ToggleGroup from '$lib/components/ui/toggle-group';
	import { roleIcon, roleLabel } from '$lib/roles';

	interface Props {
		value: string;
		onChange: (role: string) => void;
		disabled?: boolean;
	}

	let { value, onChange, disabled = false }: Props = $props();

	const roles = rolesApi.list();
	// Ownership moves through a transfer, never through a role change.
	const options = $derived((roles.data ?? []).filter((r) => r.name !== 'owner'));
	const selected = $derived(options.find((r) => r.name === value));
</script>

{#if roles.isLoading}
	<Skeleton class="h-14 w-full" />
{:else}
	<div class="flex flex-col gap-1.5">
		<ToggleGroup.Root
			type="single"
			variant="outline"
			size="sm"
			{value}
			{disabled}
			onValueChange={(v) => v && v !== value && onChange(v)}
			class="w-full"
			aria-label="Workspace role"
		>
			{#each options as role (role.name)}
				{@const Icon = roleIcon(role.name)}
				<ToggleGroup.Item value={role.name} class="flex-1 gap-1.5" title={role.description}>
					<Icon />
					{roleLabel(role.name)}
				</ToggleGroup.Item>
			{/each}
		</ToggleGroup.Root>
		<p class="min-h-4 text-xs text-muted-foreground">{selected?.description}</p>
	</div>
{/if}
