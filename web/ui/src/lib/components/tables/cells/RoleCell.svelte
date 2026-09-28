<script lang="ts">
	import { roles as rolesApi } from '$lib/api/roles.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import * as Select from '$lib/components/ui/select';
	import { roleColor, roleIcon, roleLabel } from '$lib/roles';
	import { Crown, LoaderCircle } from '@lucide/svelte';

	type Props = {
		roleName?: string;
		/** Persist a role change. If omitted, the role is shown as a badge. */
		update?: (roleName: string) => Promise<unknown> | unknown;
	};
	let { roleName = '', update }: Props = $props();

	/** Pending optimistic value while a change is being saved. */
	let optimistic = $state<string>();
	const currentRole = $derived(optimistic ?? roleName);

	const rolesQuery = $derived(rolesApi.list());
	const roleOptions = $derived(
		(rolesQuery.data ?? []).map((r) => ({
			value: r.name,
			label: roleLabel(r.name),
			description: r.description,
			icon: roleIcon(r.name),
			color: roleColor(r.name)
		}))
	);
	const selectedRole = $derived(roleOptions.find((r) => r.value === currentRole));

	let saving = $state(false);
	async function handleRoleChange(val: string) {
		if (val === currentRole || !update) return;

		optimistic = val; // Optimistically update the UI
		saving = true;
		try {
			await update(val);
		} catch {
			optimistic = undefined; // Revert to the server value
		} finally {
			saving = false;
		}
	}
</script>

{#if rolesQuery.isPending}
	<LoaderCircle class="size-3 animate-spin text-muted-foreground"></LoaderCircle>
{:else if !update || !selectedRole}
	<!-- Fixed role (e.g. owner) or read-only: shown as a badge -->
	<Badge
		variant="outline"
		class="gap-1.5 border-amber-500/30 bg-amber-500/10 text-amber-600 hover:bg-amber-500/10"
	>
		{#if roleName === 'owner'}
			<Crown />
		{/if}
		<span>{roleLabel(currentRole)}</span>
	</Badge>
{:else}
	<Select.Root type="single" value={currentRole} onValueChange={handleRoleChange}>
		<Select.Trigger
			disabled={saving}
			class="h-auto! w-fit cursor-pointer justify-center gap-1.5  rounded-full border border-input bg-transparent px-2 py-0.5 text-xs font-medium text-foreground shadow-none transition-all hover:bg-muted/50 focus:ring-0 disabled:opacity-70 [&>svg:last-child]:hidden"
		>
			{#if saving}
				<LoaderCircle class="size-3 animate-spin text-muted-foreground"></LoaderCircle>
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
