<script lang="ts">
	import * as Card from '#lib/components/ui/card/index.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import type { Principal } from '#lib/gen/nokku/v1/principal_pb.js';
	import { Users, Bot, Terminal, CircleUser } from '@lucide/svelte';
	import { Handle, Position, type NodeProps } from '@xyflow/svelte';

	let { data }: NodeProps = $props();
	let principal = $derived(data as Principal);

	let userCount = $derived((principal.userIds as string[])?.length || 0);
	let teamCount = $derived((principal.teamIds as string[])?.length || 0);
	let serviceAccountCount = $derived((principal.serviceAccountIds as string[])?.length || 0);
	let totalSubjects = $derived(userCount + teamCount + serviceAccountCount);
</script>

<div class="group relative">
	<Card.Root class="w-[280px] p-0">
		<Card.Content class="p-0">
			<div class="rounded-t-xl bg-terminal p-3 text-terminal-foreground">
				<div class="flex items-center gap-2 font-mono">
					<div class="rounded-md bg-terminal-foreground/10 p-1.5">
						<Terminal class="text-terminal-accent" size={16} />
					</div>
					<span class="text-terminal-foreground/50">$</span>
					<span class="text-lg font-bold tracking-wide text-terminal-accent"
						>{principal.username}</span
					>
				</div>
			</div>

			<div class="grid grid-cols-3 divide-x divide-border/50 border-b border-border/50">
				<div class="flex flex-col items-center py-2">
					<span class="text-lg font-bold text-foreground">{userCount}</span>
					<div
						class="flex items-center gap-1 text-2xs tracking-wider text-muted-foreground uppercase"
					>
						<CircleUser size={12} /> User
					</div>
				</div>
				<div class="flex flex-col items-center py-2">
					<span class="text-lg font-bold text-foreground">{teamCount}</span>
					<div
						class="flex items-center gap-1 text-2xs tracking-wider text-muted-foreground uppercase"
					>
						<Users size={12} /> Team
					</div>
				</div>
				<div class="flex flex-col items-center py-2">
					<span class="text-lg font-bold text-foreground">{serviceAccountCount}</span>
					<div
						class="flex items-center gap-1 text-2xs tracking-wider text-muted-foreground uppercase"
					>
						<Bot size={12} /> Service
					</div>
				</div>
			</div>

			<div class="flex items-center justify-between bg-muted/10 p-2.5 px-4 text-xs">
				<span class="text-muted-foreground">Total access grants</span>
				<Badge variant={totalSubjects > 0 ? 'default' : 'secondary'} class="h-5">
					{totalSubjects}
				</Badge>
			</div>
		</Card.Content>
	</Card.Root>

	<Handle
		type="target"
		position={Position.Top}
		class="h-3! w-3! border-4! border-background! bg-muted-foreground! transition-all hover:h-4! hover:w-4!"
	/>
	<Handle
		type="source"
		position={Position.Bottom}
		class="h-3! w-3! border-4! border-background! bg-muted-foreground! transition-all hover:h-4! hover:w-4!"
	/>
</div>
