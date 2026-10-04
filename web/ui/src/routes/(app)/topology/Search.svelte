<script lang="ts">
	import { target as targetApi } from '#lib/api/targets.svelte.js';
	import SubjectAvatar from '#lib/components/access/SubjectAvatar.svelte';
	import { useSubjectSearch } from '#lib/components/access/subjects.svelte.js';
	import SearchPopover from '#lib/components/blocks/SearchPopover.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Command from '#lib/components/ui/command/index.js';
	import { Search, Server, Tag, Terminal } from '@lucide/svelte';
	import { Debounced } from 'runed';
	import { subjectFocus, tagLabel, type Focus } from './graph.js';

	interface Props {
		accounts: string[];
		tags: string[];
		/** A target also names the tag to open, so its row shows. */
		onpick: (focus: Focus, tag?: string) => void;
	}

	let { accounts, tags, onpick }: Props = $props();

	const LOCAL = 5;

	let open = $state(false);
	let query = $state('');
	const debounced = new Debounced(() => query, 250);
	const subjects = useSubjectSearch(
		() => debounced.current,
		() => open
	);
	const targets = targetApi.list(
		() => ({ query: debounced.current || undefined, limit: 8 }),
		() => open
	);

	const needle = $derived(query.trim().toLowerCase());
	const matches = (value: string) => value.toLowerCase().includes(needle);
	const foundTags = $derived(tags.filter((t) => matches(tagLabel(t))).slice(0, LOCAL));
	const foundAccounts = $derived(accounts.filter(matches).slice(0, LOCAL));

	function pick(focus: Focus, tag?: string) {
		open = false;
		query = '';
		onpick(focus, tag);
	}
</script>

<SearchPopover
	bind:open
	bind:query
	placeholder="People, teams, targets, tags"
	loading={subjects.loading || targets.isLoading}
>
	{#snippet trigger(props)}
		<Button {...props} variant="outline" class="w-full justify-start text-muted-foreground sm:w-64">
			<Search data-icon="inline-start" />
			Find anything
		</Button>
	{/snippet}

	{#each subjects.groups as group (group.heading)}
		{#if group.items.length}
			<Command.Group heading={group.heading}>
				{#each group.items as s (s.id)}
					<Command.Item
						value={s.id}
						onSelect={() => pick({ kind: subjectFocus[s.kind], id: s.id })}
					>
						<SubjectAvatar subject={s} class="size-5" />
						<span class="truncate">{s.name}</span>
					</Command.Item>
				{/each}
			</Command.Group>
		{/if}
	{/each}
	{#if targets.data?.targets.length}
		<Command.Group heading="Targets">
			{#each targets.data.targets as t (t.id)}
				<Command.Item
					value={t.id}
					onSelect={() => pick({ kind: 'target', id: t.id }, t.tags[0] ?? '')}
				>
					<Server class="text-muted-foreground" />
					<span class="truncate">{t.name}</span>
				</Command.Item>
			{/each}
		</Command.Group>
	{/if}
	{#if foundTags.length}
		<Command.Group heading="Tags">
			{#each foundTags as tag (tag)}
				<Command.Item value={`tag:${tag}`} onSelect={() => pick({ kind: 'tag', id: tag })}>
					<Tag class="text-muted-foreground" />
					<span class="truncate">{tagLabel(tag)}</span>
				</Command.Item>
			{/each}
		</Command.Group>
	{/if}
	{#if foundAccounts.length}
		<Command.Group heading="Login accounts">
			{#each foundAccounts as username (username)}
				<Command.Item
					value={`account:${username}`}
					onSelect={() => pick({ kind: 'account', id: username })}
				>
					<Terminal class="text-muted-foreground" />
					<span class="truncate font-mono">{username}</span>
				</Command.Item>
			{/each}
		</Command.Group>
	{/if}
</SearchPopover>
