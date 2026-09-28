<script lang="ts">
	import { principal as principalApi } from '$lib/api/principals.svelte';
	import { target as targetApi } from '$lib/api/targets.svelte';
	import { MAX_PAGE_SIZE } from '$lib/config';
	import { Button, type ButtonSize, type ButtonVariant } from '$lib/components/ui/button';
	import { Checkbox } from '$lib/components/ui/checkbox';
	import * as Command from '$lib/components/ui/command';
	import * as Popover from '$lib/components/ui/popover';
	import { Spinner } from '$lib/components/ui/spinner';
	import type { Principal, SubjectKind } from '$lib/gen/nokku/v1/principal_pb';
	import type { Target } from '$lib/gen/nokku/v1/target_pb';
	import { ChevronLeft, Plus, Server } from '@lucide/svelte';
	import { Debounced } from 'runed';
	import { SvelteMap } from 'svelte/reactivity';
	import { subjectIds } from './subjects.svelte';

	interface Props {
		subjectId: string;
		kind: SubjectKind;
		/** Skips the target step, used to edit one target. */
		targetId?: string;
		label?: string;
		variant?: ButtonVariant;
		size?: ButtonSize;
	}

	let {
		subjectId,
		kind,
		targetId: fixedTarget,
		label = 'Grant access',
		variant = 'default',
		size = 'sm'
	}: Props = $props();

	let open = $state(false);
	let picked = $state<Pick<Target, 'id' | 'name'>>();
	const targetId = $derived(fixedTarget ?? picked?.id ?? '');

	let query = $state('');
	const debounced = new Debounced(() => query, 250);
	const targets = targetApi.list(
		() => ({ query: debounced.current || undefined, limit: 20 }),
		() => open && !targetId
	);

	// Only fetched while open, the subject Access tab renders one popover per target.
	const accounts = principalApi.list(() => ({
		targetId: open ? targetId : '',
		limit: MAX_PAGE_SIZE
	}));

	const addSubjects = principalApi.addSubjects();
	const removeSubjects = principalApi.removeSubjects();
	const pending = new SvelteMap<string, boolean>();

	const isGranted = (p: Principal) => pending.get(p.id) ?? subjectIds(p, kind).includes(subjectId);

	async function toggle(p: Principal, grant: boolean) {
		pending.set(p.id, grant);
		const mutation = grant ? addSubjects : removeSubjects;
		try {
			await mutation.mutateAsync({ id: p.id, subjectIds: [subjectId], kind });
		} finally {
			pending.delete(p.id);
		}
	}
</script>

<Popover.Root
	bind:open
	onOpenChange={(value) => {
		if (value) return;
		picked = undefined;
		query = '';
	}}
>
	<Popover.Trigger>
		{#snippet child({ props })}
			<Button {...props} {variant} {size}>
				{#if !fixedTarget}
					<Plus data-icon="inline-start" />
				{/if}
				{label}
			</Button>
		{/snippet}
	</Popover.Trigger>
	<Popover.Content class="w-72 p-0" align="end">
		{#if !targetId}
			<Command.Root shouldFilter={false}>
				<Command.Input bind:value={query} placeholder="Search targets..." />
				<Command.List>
					{#if targets.isLoading}
						<div class="flex justify-center py-6"><Spinner /></div>
					{:else}
						<Command.Empty>No target matches.</Command.Empty>
					{/if}
					<Command.Group heading="Targets">
						{#each targets.data?.targets ?? [] as t (t.id)}
							<Command.Item value={t.id} onSelect={() => (picked = t)}>
								<Server />
								<span class="truncate">{t.name}</span>
								<span class="ml-auto text-xs text-muted-foreground tabular-nums">
									{t.principals.length || ''}
								</span>
							</Command.Item>
						{/each}
					</Command.Group>
				</Command.List>
			</Command.Root>
		{:else}
			<div class="flex items-center gap-1 border-b p-1.5">
				{#if !fixedTarget}
					<Button
						variant="ghost"
						size="icon-sm"
						aria-label="Back"
						onclick={() => (picked = undefined)}
					>
						<ChevronLeft />
					</Button>
				{/if}
				<span class="truncate px-1.5 text-sm font-medium">
					{picked?.name ?? 'Login accounts'}
				</span>
			</div>
			<div class="flex max-h-72 flex-col overflow-y-auto p-1">
				{#if accounts.isLoading}
					<div class="flex justify-center p-4"><Spinner /></div>
				{:else}
					{#each accounts.data?.principals ?? [] as p (p.id)}
						<label
							class="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-accent"
						>
							<Checkbox checked={isGranted(p)} onCheckedChange={(v) => toggle(p, !!v)} />
							<span class="font-mono">{p.username}</span>
						</label>
					{:else}
						<p class="p-3 text-center text-xs text-muted-foreground">
							This target has no login accounts yet.
						</p>
					{/each}
				{/if}
			</div>
		{/if}
	</Popover.Content>
</Popover.Root>
