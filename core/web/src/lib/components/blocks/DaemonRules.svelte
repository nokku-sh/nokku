<script lang="ts">
	import * as Item from '#lib/components/ui/item/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import { daemonRules, type DaemonRule, type RuleValues } from '#lib/daemon-rules.js';
	import SettingRow from './SettingRow.svelte';
	import StatusDot from './StatusDot.svelte';

	interface Props {
		/** What the daemon or the workspace has now. Undefined while it loads. */
		values: RuleValues | undefined;
		/** The workspace defaults. With them a rule says when this daemon differs. */
		defaults?: RuleValues;
		disabled?: boolean;
		/** Resolves once the server has the change and the page has it back. */
		onChange: (rule: (typeof daemonRules)[number], value: boolean) => Promise<unknown>;
	}

	let { values, defaults, disabled = false, onChange }: Props = $props();

	const uid = $props.id();

	// A switch shows what was flipped until the server's copy catches up.
	let flipped = $state<RuleValues>({});
	const isOn = (key: DaemonRule) => flipped[key] ?? values?.[key] ?? false;

	async function flip(rule: (typeof daemonRules)[number], value: boolean) {
		flipped[rule.key] = value;
		try {
			await onChange(rule, value);
		} catch {
			// The global mutation handler already toasted it.
		} finally {
			delete flipped[rule.key];
		}
	}
</script>

<Item.Group class="rounded-lg border has-data-[size=sm]:gap-0">
	{#each daemonRules as rule, i (rule.key)}
		{@const on = isOn(rule.key)}
		{#if i > 0}<Item.Separator class="my-0" />{/if}
		<SettingRow
			title={rule.title}
			description={rule.description}
			directive={rule.directive}
			for={`${uid}-${rule.key}`}
		>
			{#snippet note()}
				{#if defaults && values && on !== (defaults[rule.key] ?? false)}
					<p class="flex items-center gap-1.5 text-xs text-info">
						<StatusDot tone="info" class="size-1.5" />
						{on ? 'On' : 'Off'} here, the workspace default is {on ? 'off' : 'on'}
					</p>
				{/if}
			{/snippet}
			{#if values}
				<Switch
					id={`${uid}-${rule.key}`}
					checked={on}
					disabled={disabled || rule.key in flipped}
					onCheckedChange={(v) => flip(rule, v)}
				/>
			{:else}
				<Skeleton class="h-5 w-9 rounded-full" />
			{/if}
		</SettingRow>
	{/each}
</Item.Group>
