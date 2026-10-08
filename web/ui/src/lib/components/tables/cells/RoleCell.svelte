<script lang="ts">
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { roles as rolesApi } from '#lib/api/roles.svelte.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import { parseRole, roleColor, roleIcon, roleLabel, roleSlug } from '#lib/roles.js';
	import { Crown } from '@lucide/svelte';

	type Props = {
		role?: WorkspaceRole;
		/** Persist a role change. If omitted, the role is shown as a badge. */
		update?: (role: WorkspaceRole) => Promise<unknown> | unknown;
		/** The highest role on offer. */
		max?: WorkspaceRole;
	};
	let { role = WorkspaceRole.UNSPECIFIED, update, max = WorkspaceRole.ADMIN }: Props = $props();

	let optimistic = $state<WorkspaceRole>();
	const currentRole = $derived(optimistic ?? role);

	const rolesQuery = rolesApi.list();
	const roleOptions = $derived(
		(rolesQuery.data ?? [])
			.filter((r) => r.role <= max)
			.map((r) => ({
				role: r.role,
				// The select speaks strings.
				value: roleSlug(r.role),
				label: roleLabel(r.role),
				description: r.description,
				icon: roleIcon(r.role),
				color: roleColor(r.role)
			}))
	);
	const selectedRole = $derived(roleOptions.find((r) => r.role === currentRole));

	let saving = $state(false);
	async function handleRoleChange(slug: string) {
		const picked = parseRole(slug);
		if (!picked || picked === currentRole || !update) return;

		optimistic = picked; // Optimistically update the UI
		saving = true;
		try {
			await update(picked);
		} catch {
			optimistic = undefined; // Revert to the server value
		} finally {
			saving = false;
		}
	}
</script>

{#if rolesQuery.isPending}
	<Spinner class="size-3 text-muted-foreground" />
{:else if !update || !selectedRole}
	<Badge
		variant="outline"
		class="gap-1.5 border-warning/30 bg-warning/10 text-warning hover:bg-warning/10"
	>
		{#if role === WorkspaceRole.OWNER}
			<Crown />
		{/if}
		<span>{roleLabel(currentRole)}</span>
	</Badge>
{:else}
	<Select.Root type="single" value={roleSlug(currentRole)} onValueChange={handleRoleChange}>
		<Select.Trigger
			disabled={saving}
			class="h-auto! w-fit cursor-pointer justify-center gap-1.5 rounded-full border border-input bg-transparent px-2 py-0.5 text-xs font-medium text-foreground transition-all hover:bg-muted/50 focus:ring-0 disabled:opacity-70 [&>svg:last-child]:hidden"
		>
			{#if saving}
				<Spinner class="size-3 text-muted-foreground" />
				<span class="text-muted-foreground">Saving...</span>
			{:else}
				<selectedRole.icon class="size-3 {selectedRole.color}"></selectedRole.icon>
				<span>{selectedRole.label}</span>
			{/if}
		</Select.Trigger>

		<Select.Content class="max-w-80">
			<Select.Group>
				{#each roleOptions as role (role.value)}
					<Select.Item
						value={role.value}
						label={role.label}
						class="cursor-pointer items-center gap-3 py-2.5"
					>
						<div
							class="mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-md bg-muted/50"
						>
							<role.icon class="size-4 {role.color}"></role.icon>
						</div>
						<div class="flex flex-col gap-1 text-left">
							<span class="text-sm leading-none font-medium">{role.label}</span>
							<span class="text-xs leading-snug text-muted-foreground">{role.description}</span>
						</div>
					</Select.Item>
				{/each}
			</Select.Group>
		</Select.Content>
	</Select.Root>
{/if}
