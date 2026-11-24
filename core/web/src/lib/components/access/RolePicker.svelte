<script lang="ts">
	import * as ToggleGroup from '#lib/components/ui/toggle-group/index.js';
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import { assignableRoles, parseRole, roleIcon, roleLabel, roleSlug } from '#lib/roles.js';

	interface Props {
		value: WorkspaceRole;
		onChange: (role: WorkspaceRole) => void;
		/** The highest role on offer. Ownership moves through a transfer, never through a role change. */
		max?: WorkspaceRole;
		disabled?: boolean;
		/** For a service account. Its editor adds servers, access is for people to change. */
		machine?: boolean;
	}

	let {
		value,
		onChange,
		max = WorkspaceRole.ADMIN,
		disabled = false,
		machine = false
	}: Props = $props();

	const options = $derived(assignableRoles.filter((r) => r.role <= max));
	const selected = $derived(options.find((r) => r.role === value));
	const description = $derived(
		machine && value === WorkspaceRole.EDITOR
			? 'Also add and remove servers with nk sync. Only people change who has access'
			: selected?.description
	);

	// The toggle group speaks strings.
	function pick(slug: string) {
		const role = parseRole(slug);
		if (role && role !== value) onChange(role);
	}
</script>

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
	<p class="min-h-4 text-xs text-muted-foreground">{description}</p>
</div>
