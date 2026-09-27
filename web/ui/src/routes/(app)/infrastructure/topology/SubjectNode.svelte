<script lang="ts">
	import { principal } from '$lib/api/principals.svelte';
	import DeleteConfirmationModal from '$lib/components/modals/DeleteConfirmationModal.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import { SubjectKind } from '$lib/gen/nokku/v1/principal_pb';
	import { type ServiceAccount } from '$lib/gen/nokku/v1/service_account_pb';
	import type { Team } from '$lib/gen/nokku/v1/team_pb';
	import type { User } from '$lib/gen/nokku/v1/account_pb';
	import { formatTs } from '$lib/utils';
	import {
		Users,
		Bot,
		Mail,
		Trash2,
		Waypoints,
		CircleUserIcon,
		UsersIcon,
		Clock
	} from '@lucide/svelte';
	import { Handle, Position, type NodeProps } from '@xyflow/svelte';

	let { data }: NodeProps = $props();
	let subjectType = $derived(data.subjectType as SubjectKind);

	let openRevokeModal = $state(false);

	const config = $derived.by(() => {
		switch (subjectType) {
			case SubjectKind.USER:
				return {
					borderColor: 'border-blue-500',
					headerBg: 'bg-blue-500/10',
					iconColor: 'text-blue-500',
					icon: CircleUserIcon,
					label: 'User',
					handleColor: 'bg-blue-500!'
				};
			case SubjectKind.TEAM:
				return {
					borderColor: 'border-emerald-500',
					headerBg: 'bg-emerald-500/10',
					iconColor: 'text-emerald-500',
					icon: UsersIcon,
					label: 'Team',
					handleColor: 'bg-emerald-500!'
				};
			case SubjectKind.SERVICE_ACCOUNT:
				return {
					borderColor: 'border-purple-500',
					headerBg: 'bg-purple-500/10',
					iconColor: 'text-purple-500',
					icon: Waypoints,
					label: 'Service',
					handleColor: 'bg-purple-500!'
				};
			default:
				return {
					borderColor: 'border-purple-500',
					headerBg: 'bg-purple-500/10',
					iconColor: 'text-purple-500',
					icon: Bot,
					label: 'Service',
					handleColor: 'bg-purple-500!'
				};
		}
	});

	const revokeAccessTarget = principal.removeSubjects();
	function handleRevokeAccess() {
		if (!data.subjectType || !data.principalId) return;
		let subjectID = data.id as User['id'] | Team['id'] | ServiceAccount['id'];
		revokeAccessTarget.mutate({
			id: data.principalId as string,
			subjectIds: [subjectID],
			kind: data.subjectType as SubjectKind
		});
	}
</script>

<DeleteConfirmationModal
	bind:open={openRevokeModal}
	title="Revoke Access"
	description="This will revoke access to {data.name}"
	itemName={(data.name as string) || (data.username as string) || ''}
	onConfirm={handleRevokeAccess}
/>

<div class="group relative">
	<Card.Root
		class="w-[250px] overflow-hidden border-l-4 border-border/60 bg-card transition-all duration-300 hover:shadow-lg {config.borderColor}"
	>
		<div class="flex items-center justify-between px-4">
			<div class="flex items-center gap-3 overflow-hidden">
				<div
					class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full {config.headerBg}"
				>
					<config.icon size={20} class={config.iconColor} />
				</div>

				<div class="flex min-w-0 flex-col">
					<h4 class="truncate text-sm leading-none font-semibold text-foreground">
						{data.name || data.username}
					</h4>
					<div class="mt-1 flex items-center gap-1.5 text-xs text-muted-foreground">
						{#if subjectType === SubjectKind.USER && data.email}
							<Mail class="h-3 w-3 shrink-0" />
							<span class="truncate">{data.email}</span>
						{:else if subjectType === SubjectKind.TEAM}
							<Users class="h-3 w-3 shrink-0" />
							<span>{config.label}</span>
						{:else if subjectType === SubjectKind.SERVICE_ACCOUNT}
							{@const sa = data as ServiceAccount}
							<Clock class="h-3 w-3 shrink-0" />

							<span
								class="truncate font-mono text-[10px]"
								title={formatTs(sa.expiresAt, 'relative')}
							>
								expires
								{formatTs(sa.expiresAt, 'relative')}
							</span>
						{/if}
					</div>
				</div>
			</div>
		</div>
		<Button
			variant="ghost"
			size="icon"
			class="absolute -top-4 -right-4 rounded-full hover:text-destructive {config.handleColor} text-white"
			onclick={() => (openRevokeModal = true)}
		>
			<Trash2 size={14} />
		</Button>
	</Card.Root>

	<Handle
		type="target"
		position={Position.Top}
		class="h-2.5! w-2.5! border-2! border-background! transition-all hover:h-3.5! hover:w-3.5! {config.handleColor}"
	/>
</div>
