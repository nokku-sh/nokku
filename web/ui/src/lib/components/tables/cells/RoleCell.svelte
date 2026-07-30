<script lang="ts">
	import { workspace } from '$lib/api/workspaces.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import * as Select from '$lib/components/ui/select';
	import type { WorkspaceMember } from '$lib/gen/nokku/v1/workspace_pb';
	import { Crown, LoaderCircle, ShieldCheck, ShieldIcon, User } from '@lucide/svelte';

	interface Props {
		user: WorkspaceMember;
	}
	let { user = $bindable() }: Props = $props();

	let currentRole = $state(user.roleName);

	const roles = [
		{
			value: 'member',
			label: 'Member',
			description: 'View workspace resources',
			icon: User,
			color: 'text-blue-500'
		},
		{
			value: 'admin',
			label: 'Admin',
			description: 'Manage operational resources',
			icon: ShieldCheck,
			color: 'text-indigo-500'
		}
	];

	const updateMember = workspace.updateMember();
	function handleRoleChange(val: string) {
		if (val === currentRole) return;

		const previousRole = currentRole;
		currentRole = val; // Instantly update the UI

		updateMember.mutate(
			{ userId: user.id, roleName: val },
			{ onError: () => (currentRole = previousRole) }
		);
	}

	let selectedRole = $derived(roles.find((r) => r.value === currentRole));
</script>

{#if user.roleName === 'owner'}
	<Badge
		variant="outline"
		class="gap-1.5 border-amber-500/30 bg-amber-500/10 text-amber-600 hover:bg-amber-500/10"
	>
		<Crown />
		<span>Owner</span>
	</Badge>
{:else}
	<Select.Root type="single" value={currentRole} onValueChange={handleRoleChange}>
		<Select.Trigger
			disabled={updateMember.isPending}
			class="h-auto! w-fit justify-center gap-1.5 rounded-full border border-input bg-transparent px-2 py-0.5 text-xs font-medium text-foreground shadow-none transition-all hover:bg-muted/50 focus:ring-0 disabled:opacity-70 [&>svg:last-child]:hidden"
		>
			{#if updateMember.isPending}
				<LoaderCircle class="size-3 animate-spin text-muted-foreground" />
				<span class="text-muted-foreground">Saving...</span>
			{:else if selectedRole}
				<selectedRole.icon class="size-3 {selectedRole.color}" />
				<span>{selectedRole.label}</span>
			{:else}
				<ShieldIcon class="size-3 text-muted-foreground" />
				<span class="capitalize">{currentRole}</span>
			{/if}
		</Select.Trigger>

		<Select.Content class="max-w-80">
			<Select.Group>
				{#each roles as role}
					<Select.Item
						value={role.value}
						label={role.label}
						class="cursor-pointer items-center gap-3 py-2.5"
					>
						<div
							class="mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-md bg-muted/50"
						>
							<role.icon class="size-4 {role.color}" />
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
