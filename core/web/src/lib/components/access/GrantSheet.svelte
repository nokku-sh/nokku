<script lang="ts">
	import { plural } from '#lib/api/bulk.js';
	import { targetAccount } from '#lib/api/target-accounts.svelte.js';
	import { target as targetApi } from '#lib/api/targets.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { useFeatures } from '#lib/api/workspaces.svelte.js';
	import Chip from '#lib/components/blocks/Chip.svelte';
	import PlanBadge from '#lib/components/blocks/PlanBadge.svelte';
	import SearchPopover from '#lib/components/blocks/SearchPopover.svelte';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Checkbox } from '#lib/components/ui/checkbox/index.js';
	import * as Command from '#lib/components/ui/command/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import * as Sheet from '#lib/components/ui/sheet/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import * as ToggleGroup from '#lib/components/ui/toggle-group/index.js';
	import type { Target } from '#lib/gen/nokku/v1/target_pb.js';
	import { confirm, IsMobile } from '#lib/hooks/index.js';
	import { formatHours, formatTs, listNames } from '#lib/utils.js';
	import { Check, Plus, Server, Tag } from '@lucide/svelte';
	import { Debounced } from 'runed';
	import { toast } from 'svelte-sonner';
	import { grantSheet, subjectLabel } from './grant.svelte';
	import SubjectAvatar from './SubjectAvatar.svelte';
	import SubjectPicker from './SubjectPicker.svelte';
	import { grantEnd, type Subject } from './subjects.svelte';

	const can = user.can();
	const has = useFeatures();
	const mobile = new IsMobile();

	const LENGTHS = [0, 1, 8, 24, 24 * 7, 24 * 30];
	// Past this many servers, or on root, the grant asks once more before it runs.
	const CAREFUL = 10;

	const picked = $derived(grantSheet.servers.length + grantSheet.tags.length > 0);
	const whereSpec = () => ({
		targetIds: grantSheet.servers.map((s) => s.id),
		tags: grantSheet.tags
	});
	// The core says which servers these are and what the grant does there. The sheet only shows it.
	const where = targetAccount.planGrant(whereSpec, () => grantSheet.open && can.edit && picked);
	const servers = $derived(picked ? (where.data?.plan?.servers ?? 0) : 0);
	const finding = $derived(picked && where.isFetching);

	const accounts = $derived(picked ? (where.data?.plan?.accounts ?? []) : []);
	// The only account there is picks itself.
	const account = $derived(
		grantSheet.account || (accounts.length === 1 ? accounts[0].username : '')
	);
	const accountChoices = $derived(
		account && !accounts.some((a) => a.username === account)
			? [...accounts, { username: account, servers: 0 }]
			: accounts
	);

	const end = $derived(grantEnd(grantSheet.hours));
	const spec = $derived({
		...whereSpec(),
		subjects: grantSheet.subjects.map(({ id, kind }) => ({ id, kind })),
		username: account,
		expiresAt: end,
		changeEnds: grantSheet.changeEnds
	});
	const planned = targetAccount.planGrant(
		() => spec,
		() => grantSheet.open && can.edit && !!account && servers > 0
	);
	const plan = $derived(account && servers ? planned.data?.plan : undefined);
	const rows = $derived(
		grantSheet.subjects.flatMap((subject) => {
			const outcome = plan?.outcomes.find((o) => o.subjectId === subject.id);
			return outcome ? [{ subject, ...outcome }] : [];
		})
	);
	const added = $derived(rows.reduce((n, r) => n + r.added, 0));
	const otherEnd = $derived(rows.reduce((n, r) => n + r.otherEnd, 0));
	const changes = $derived(added + (grantSheet.changeEnds ? otherEnd : 0));
	const skipped = $derived(plan ? plan.servers - plan.withAccount : 0);
	const ready = $derived(
		can.edit &&
			grantSheet.subjects.length > 0 &&
			!!plan &&
			changes > 0 &&
			!finding &&
			!planned.isFetching
	);

	const endText = $derived(
		end
			? `Ends ${formatTs(end, 'withTime')}, by itself.`
			: 'No end. It stays until someone removes it.'
	);
	const whereText = $derived.by(() => {
		if (!picked) return 'Pick servers by name, or a tag for all its servers.';
		if (finding && !servers) return '';
		if (!servers) return 'No server has these tags yet.';
		return `${plural(servers, 'server')}: ${listNames(where.data?.plan?.serverNames ?? [], 3, servers)}`;
	});
	const previewTitle = $derived.by(() => {
		if (!plan) return '';
		if (!plan.withAccount) return `No server here has a ${account} account.`;
		if (!changes) return 'Nothing to change, they have it already.';
		const moved = grantSheet.changeEnds ? otherEnd : 0;
		return [added && `${plural(added, 'new grant')}`, moved && `${plural(moved, 'new end')}`]
			.filter(Boolean)
			.join(' and ')
			.concat(` on ${plural(plan.withAccount, 'server')}`);
	});

	const grant = targetAccount.grant();

	async function submit() {
		if (!ready || !plan) return;
		const on = plural(plan.withAccount, 'server');
		const done = added ? `Granted ${account} on ${on}` : `New end for ${account} on ${on}`;
		// One call and one transaction, so it lands whole or not at all. The end counts from now.
		const run = async () => {
			await grant.mutateAsync({ grant: { ...spec, expiresAt: grantEnd(grantSheet.hours) } });
			toast.success(done);
			grantSheet.open = false;
		};
		if (account === 'root' || plan.withAccount > CAREFUL) {
			const who = listNames(grantSheet.subjects.map(subjectLabel));
			await confirm({
				title: `Grant ${account} on ${on}?`,
				description: `${who} can then log in as ${account}${account === 'root' ? ', a superuser,' : ''} on ${on}. ${endText}`,
				confirmText: 'Grant',
				destructive: false,
				onConfirm: run
			});
			return;
		}
		try {
			await run();
		} catch {
			// The mutation already toasted it.
		}
	}

	function toggleSubject(s: Subject, on: boolean) {
		grantSheet.subjects = on
			? [...grantSheet.subjects, s]
			: grantSheet.subjects.filter((x) => x.id !== s.id);
	}
	function toggleTag(tag: string) {
		grantSheet.tags = grantSheet.tags.includes(tag)
			? grantSheet.tags.filter((t) => t !== tag)
			: [...grantSheet.tags, tag];
	}
	function toggleServer(t: Pick<Target, 'id' | 'name'>) {
		grantSheet.servers = grantSheet.servers.some((s) => s.id === t.id)
			? grantSheet.servers.filter((s) => s.id !== t.id)
			: [...grantSheet.servers, { id: t.id, name: t.name }];
	}

	let whereOpen = $state(false);
	let whereQuery = $state('');
	const typed = new Debounced(() => whereQuery.trim(), 250);
	const found = targetApi.list(
		() => ({ query: typed.current || undefined, limit: 20 }),
		() => whereOpen
	);
	const filters = targetApi.filters(() => whereOpen);
	const tagMatches = $derived(
		(filters.data?.tags ?? [])
			.filter((t) => t.toLowerCase().includes(whereQuery.trim().toLowerCase()))
			.slice(0, 8)
	);
</script>

<!-- Mounted on open, so it lands on top of a sheet it was opened from. -->
{#if grantSheet.open}
	<Sheet.Root bind:open={grantSheet.open}>
		<Sheet.Content
			side={mobile.current ? 'bottom' : 'right'}
			class="w-full gap-0 p-0 data-[side=bottom]:max-h-[92dvh] data-[side=bottom]:rounded-t-2xl data-[side=right]:sm:max-w-xl"
		>
			<Sheet.Header class="border-b px-5 pt-5 pb-4">
				<Sheet.Title class="text-lg">Grant access</Sheet.Title>
				<Sheet.Description>
					Pick who, where and as which account. Nothing changes until you press Grant.
				</Sheet.Description>
			</Sheet.Header>

			<div class="flex min-h-0 flex-1 flex-col gap-6 overflow-y-auto px-5 py-5">
				<Field.Set>
					<Field.Legend variant="label">Who</Field.Legend>
					<div class="flex flex-wrap items-center gap-1.5">
						{#each grantSheet.subjects as s (s.id)}
							<Chip
								label={subjectLabel(s)}
								title={s.detail}
								onRemove={() => toggleSubject(s, false)}
							>
								{#snippet leading()}
									<SubjectAvatar subject={s} class="size-6" />
								{/snippet}
							</Chip>
						{/each}
						<SubjectPicker
							selected={grantSheet.subjects.map((s) => s.id)}
							onToggle={toggleSubject}
							label={grantSheet.subjects.length ? 'Add' : 'Pick who'}
						/>
					</div>
					<Field.Description>
						People, teams or service accounts. Every member of a team gets it.
					</Field.Description>
				</Field.Set>

				<Field.Set>
					<Field.Legend variant="label">Where</Field.Legend>
					<div class="flex flex-wrap items-center gap-1.5">
						{#each grantSheet.tags as tag (tag)}
							<Chip
								label={tag}
								mono
								onRemove={() => toggleTag(tag)}
								removeLabel={`Remove tag ${tag}`}
							>
								{#snippet leading()}
									<Tag class="ml-2 size-3 text-muted-foreground" />
								{/snippet}
							</Chip>
						{/each}
						{#each grantSheet.servers as s (s.id)}
							<Chip label={s.name} mono onRemove={() => toggleServer(s)}>
								{#snippet leading()}
									<Server class="ml-2 size-3 text-muted-foreground" />
								{/snippet}
							</Chip>
						{/each}
						<SearchPopover
							bind:open={whereOpen}
							bind:query={whereQuery}
							placeholder="Search servers or tags..."
							empty="Nothing matches."
							loading={found.isLoading}
						>
							{#snippet trigger(props)}
								<Button {...props} variant="outline" size="sm">
									<Plus data-icon="inline-start" />
									{picked ? 'Add' : 'Pick where'}
								</Button>
							{/snippet}
							{#if tagMatches.length}
								<Command.Group heading="Tags">
									{#each tagMatches as tag (tag)}
										<Command.Item value={`tag:${tag}`} onSelect={() => toggleTag(tag)}>
											<Tag />
											<span class="flex-1 truncate font-mono">{tag}</span>
											<Check class={grantSheet.tags.includes(tag) ? 'text-primary' : 'invisible'} />
										</Command.Item>
									{/each}
								</Command.Group>
							{/if}
							{#if found.data?.targets.length}
								<Command.Group heading="Servers">
									{#each found.data.targets as t (t.id)}
										{@const on = grantSheet.servers.some((s) => s.id === t.id)}
										<Command.Item value={t.id} onSelect={() => toggleServer(t)}>
											<Server />
											<span class="flex-1 truncate">{t.name}</span>
											<Check class={on ? 'text-primary' : 'invisible'} />
										</Command.Item>
									{/each}
								</Command.Group>
							{/if}
						</SearchPopover>
					</div>
					{#if finding && !servers}
						<Skeleton class="h-4 w-48" />
					{:else}
						<Field.Description>{whereText}</Field.Description>
					{/if}
				</Field.Set>

				<Field.Set>
					<Field.Legend variant="label">As</Field.Legend>
					{#if accountChoices.length}
						<ToggleGroup.Root
							type="single"
							variant="outline"
							size="sm"
							spacing={1}
							class="flex-wrap"
							aria-label="Login account"
							value={account}
							onValueChange={(v) => (grantSheet.account = v)}
						>
							{#each accountChoices as a (a.username)}
								<ToggleGroup.Item value={a.username} class="gap-2">
									<span class="font-mono">{a.username}</span>
									<span class="text-xs text-muted-foreground tabular-nums">
										{a.servers}/{servers}
									</span>
								</ToggleGroup.Item>
							{/each}
						</ToggleGroup.Root>
						<Field.Description>
							{#if account === 'root'}
								<Badge variant="warning">Superuser</Badge>
							{/if}
							The count says on how many of the servers the account exists.
						</Field.Description>
					{:else}
						<Field.Description>
							{picked ? 'These servers have no login accounts yet.' : 'Pick where first.'}
						</Field.Description>
					{/if}
				</Field.Set>

				<Field.Set>
					<Field.Legend variant="label" class="flex items-center gap-2">
						How long <PlanBadge feature="expiring_access" />
					</Field.Legend>
					<ToggleGroup.Root
						type="single"
						variant="outline"
						size="sm"
						spacing={1}
						class="flex-wrap"
						aria-label="How long"
						value={String(grantSheet.hours)}
						onValueChange={(v) => v && (grantSheet.hours = Number(v))}
					>
						{#each LENGTHS as h (h)}
							<ToggleGroup.Item
								value={String(h)}
								disabled={h > 0 && has('expiring_access') !== true}
							>
								{h ? formatHours(h) : 'For good'}
							</ToggleGroup.Item>
						{/each}
					</ToggleGroup.Root>
					<Field.Description>{endText}</Field.Description>
					{#if otherEnd || grantSheet.changeEnds}
						<Field.Field orientation="horizontal">
							<Checkbox id="grant-change-ends" bind:checked={grantSheet.changeEnds} />
							<Field.Content>
								<Field.Label for="grant-change-ends">
									Give the {plural(otherEnd, 'grant')} they hold already this end too
								</Field.Label>
								<Field.Description>Left alone, those keep the end they have now.</Field.Description>
							</Field.Content>
						</Field.Field>
					{/if}
				</Field.Set>

				{#if plan && grantSheet.subjects.length}
					<section
						aria-labelledby="grant-preview"
						class="flex flex-col gap-3 rounded-lg border bg-muted/40 p-4"
					>
						<h3 id="grant-preview" class="text-sm font-medium">{previewTitle}</h3>
						<ul class="flex flex-col gap-2">
							{#each rows as row (row.subject.id)}
								<li class="flex flex-wrap items-center gap-2 text-sm">
									<SubjectAvatar subject={row.subject} class="size-6" />
									<span class="min-w-0 flex-1 truncate">{subjectLabel(row.subject)}</span>
									{#if row.added}<Badge variant="success">{row.added} new</Badge>{/if}
									{#if row.same}<Badge variant="muted">{row.same} already</Badge>{/if}
									{#if row.otherEnd}
										<Badge variant="warning">
											{row.otherEnd}
											{grantSheet.changeEnds ? 'get this end' : 'keep their end'}
										</Badge>
									{/if}
								</li>
							{/each}
						</ul>
						{#if skipped}
							<p class="text-xs text-muted-foreground">
								{listNames(plan.skipped, 3, skipped)}
								{skipped === 1 ? 'has' : 'have'} no {account} account, so
								{skipped === 1 ? 'it is' : 'they are'} skipped.
							</p>
						{/if}
					</section>
				{/if}
			</div>

			<Sheet.Footer class="flex-row justify-end gap-2 border-t px-5 py-3">
				<Button variant="outline" onclick={() => (grantSheet.open = false)}>Cancel</Button>
				<Button onclick={submit} disabled={!ready || grant.isPending}>
					{#if grant.isPending}<Spinner data-icon="inline-start" />{/if}
					Grant
				</Button>
			</Sheet.Footer>
		</Sheet.Content>
	</Sheet.Root>
{/if}
