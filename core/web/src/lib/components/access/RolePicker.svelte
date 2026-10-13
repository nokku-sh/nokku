<script lang="ts">
	import { roles as rolesApi } from '#lib/api/roles.svelte.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import * as ToggleGroup from '#lib/components/ui/toggle-group/index.js';
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import { parseRole, roleIcon, roleLabel, roleSlug } from '#lib/roles.js';

	interface Props {
		value: WorkspaceRole;
		onChange: (role: WorkspaceRole) => void;
		/** The highest role on offer. Ownership moves through a transfer, never through a role change. */
		max?: WorkspaceRole;
		disabled?: boolean;
	}

	let { value, onChange, max = WorkspaceRole.ADMIN, disabled = false }: Props = $props();

	const roles = rolesApi.list();
	const options = $derived((roles.data ?? []).filter((r) => r.role <= max));
	const selected = $derived(options.find((r) => r.role === value));

	// The toggle group speaks strings.
	function pick(slug: string) {
		const role = parseRole(slug);
		if (role && role !== value) onChange(role);
	}
</script>

{#if roles.isLoading}
	<Skeleton class="h-14 w-full" />
{:else}
	<div class="flex flex-col gap-1.5">
		<ToggleGroup.Root
			type="single"
			variant="outline"
			size="sm"
			value={roleSlug(value)}
			{disabled}
			onValueChange={pick}
			class="w-full"
			aria-label="Workspace role"
		>
			{#each options as option (option.role)}
				{@const Icon = roleIcon(option.role)}
				<ToggleGroup.Item
					value={roleSlug(option.role)}
					class="flex-1 gap-1.5"
					title={option.description}
				>
					<Icon />
					{roleLabel(option.role)}
				</ToggleGroup.Item>
			{/each}
		</ToggleGroup.Root>
		<p class="min-h-4 text-xs text-muted-foreground">{selected?.description}</p>
	</div>
{/if}
