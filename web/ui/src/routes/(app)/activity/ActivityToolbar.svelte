<script lang="ts">
	import { workspace } from '$lib/api/workspaces.svelte';
	import type { FacetedFilter } from '$lib/components/tables/types';
	import { InputGroupVariants } from '$lib/components/ui/input-group';
	import FacetedFilterButton from '$lib/components/utils/FacetedFilterButton.svelte';
	import {
		CirclePlus,
		Pencil,
		Trash2,
		Plus,
		Minus,
		KeyRound,
		Bot,
		CircleUser,
		ShieldCheck
	} from '@lucide/svelte';
	import { SvelteSet } from 'svelte/reactivity';

	interface Props {
		search?: string;
		searchResults?: number;
		selectedActions: SvelteSet<string>;
		selectedActorTypes: SvelteSet<string>;
		selectedUsers: SvelteSet<string>;
	}
	let {
		search = $bindable(),
		searchResults,
		selectedActions,
		selectedActorTypes,
		selectedUsers
	}: Props = $props();

	let actionFilter: FacetedFilter[] = [
		{
			label: 'Create',
			value: 'create',
			icon: CirclePlus
		},
		{
			label: 'Update',
			value: 'update',
			icon: Pencil
		},
		{
			label: 'Delete',
			value: 'delete',
			icon: Trash2
		},
		{
			label: 'Add',
			value: 'add',
			icon: Plus
		},
		{
			label: 'Remove',
			value: 'remove',
			icon: Minus
		},
		{
			label: 'Sign',
			value: 'sign',
			icon: KeyRound
		},
		{
			label: 'Login',
			value: 'login',
			icon: CircleUser
		}
	];
	let actorTypeFilter: FacetedFilter[] = [
		{
			label: 'User',
			value: 'user',
			icon: CircleUser
		},
		{
			label: 'Daemon',
			value: 'daemon',
			icon: Bot
		},
		{
			label: 'System',
			value: 'system',
			icon: ShieldCheck
		}
	];
	const members = $derived(workspace.listMembers());
	let userFilter: FacetedFilter[] = $derived.by(() => {
		return (
			members.data?.members.map((member) => ({
				label: member.name,
				value: member.id,
				icon: CircleUser
			})) || []
		);
	});
</script>

<!-- Custom Toolbar -->
<div class="flex items-center gap-2">
	<InputGroupVariants
		variant="search"
		bind:value={search}
		class="max-w-sm sm:min-w-sm"
		{searchResults}
	/>

	<FacetedFilterButton bind:values={selectedActions} options={actionFilter} title="Action" />
	<FacetedFilterButton
		bind:values={selectedActorTypes}
		options={actorTypeFilter}
		title="Actor Types"
	/>
	<FacetedFilterButton bind:values={selectedUsers} options={userFilter} title="Users" />
</div>
