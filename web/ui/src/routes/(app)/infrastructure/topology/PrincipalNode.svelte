<script lang="ts">
	import * as Card from '$lib/components/ui/card';
	import { Badge } from '$lib/components/ui/badge';
	import type { Principal } from '$lib/gen/nokku/v1/principal_pb';
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
			<!-- Header -->
			<div class="rounded-t-xl border-b p-3 dark:bg-zinc-900">
				<div class="flex items-center gap-2 font-mono">
					<div class="rounded bg-zinc-900 p-1.5 backdrop-blur dark:bg-white/10">
						<Terminal class="text-emerald-400" size={16} />
					</div>
					<span class="dark:text-zinc-500">$</span>
					<span class="text-lg font-bold tracking-wide text-emerald-400">{principal.username}</span>
				</div>
			</div>

			<!-- Stats Row -->
			<div class="grid grid-cols-3 divide-x divide-border/50 border-b border-border/50">
				<div class="flex flex-col items-center py-2">
					<span class="text-lg font-bold text-foreground">{userCount}</span>
					<div
						class="flex items-center gap-1 text-[10px] tracking-wider text-muted-foreground uppercase"
					>
						<CircleUser size={12} /> User
					</div>
				</div>
				<div class="flex flex-col items-center py-2">
					<span class="text-lg font-bold text-foreground">{teamCount}</span>
					<div
						class="flex items-center gap-1 text-[10px] tracking-wider text-muted-foreground uppercase"
					>
						<Users size={12} /> Team
					</div>
				</div>
				<div class="flex flex-col items-center py-2">
					<span class="text-lg font-bold text-foreground">{serviceAccountCount}</span>
					<div
						class="flex items-center gap-1 text-[10px] tracking-wider text-muted-foreground uppercase"
					>
						<Bot size={12} /> Service
					</div>
				</div>
			</div>

			<!-- Footer -->
			<div class="flex items-center justify-between bg-muted/10 p-2.5 px-4 text-xs">
				<span class="text-muted-foreground">Total Access Grants</span>
				<Badge variant={totalSubjects > 0 ? 'default' : 'secondary'} class="h-5">
					{totalSubjects}
				</Badge>
			</div>
		</Card.Content>
	</Card.Root>

	<Handle
		type="target"
		position={Position.Top}
		class="h-3! w-3! border-4! border-background! bg-slate-500! transition-all hover:h-4! hover:w-4!"
	/>
	<Handle
		type="source"
		position={Position.Bottom}
		class="h-3! w-3! border-4! border-background! bg-slate-500! transition-all hover:h-4! hover:w-4!"
	/>
</div>
