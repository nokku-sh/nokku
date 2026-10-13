<script lang="ts">
	import { util } from '#lib/api/workspaces.svelte.js';
	import TokenSheet from '#lib/components/sheets/TokenSheet.svelte';
	import * as Alert from '#lib/components/ext/alert/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import CodeSnippet from '#lib/components/blocks/CodeSnippet.svelte';
	import CopyText from '#lib/components/blocks/CopyText.svelte';
	import { JoinTokenKind } from '#lib/gen/nokku/v1/join_token_pb.js';
	import { Info, Rocket } from '@lucide/svelte';

	let { open = $bindable(false) }: { open?: boolean } = $props();

	// The installer needs root. Ansible and cloud-init already run as root.
	const installer = 'curl -fsSL https://get.nokku.sh/nokkud';
	// nokkud talks to app.nokku.sh unless told otherwise, self-hosted needs the URL.
	const selfHosted = location.origin !== 'https://app.nokku.sh';
	// A server behind a private CA names its pin, nokkud checks the CA against it.
	const info = util.instanceInfo();
	const pin = $derived(info.data?.caPin ?? '');
	const apiEnv = $derived(
		(selfHosted ? `NOKKUD_API_URL=${location.origin} ` : '') + (pin ? `NOKKUD_API_PIN=${pin} ` : '')
	);

	function envFlags(token: string) {
		return [
			`NOKKUD_ENROLL_TOKEN='${token}'`,
			...(selfHosted ? [`NOKKUD_API_URL=${location.origin}`] : []),
			...(pin ? [`NOKKUD_API_PIN=${pin}`] : [])
		];
	}

	function snippets(token: string) {
		return [
			{
				value: 'host',
				label: 'One host',
				language: 'bash',
				hint: 'Paste the token when nokkud asks for it. It never ends up in your shell history.',
				code: [
					`${installer} | sudo sh`,
					`sudo ${apiEnv}nokkud enroll`,
					'sudo systemctl restart nokkud'
				].join('\n')
			},
			{
				value: 'script',
				label: 'Script',
				language: 'bash',
				hint: 'Unattended. The token goes in through the environment, never as an argument.',
				code: [
					`${installer} | sudo sh`,
					`sudo NOKKUD_ENROLL_TOKEN='${token}' ${apiEnv}nokkud enroll`,
					'sudo systemctl restart nokkud'
				].join('\n')
			},
			{
				value: 'ansible',
				label: 'Ansible',
				language: 'yaml',
				hint: 'Idempotent, reruns skip enrolled hosts. Keep the token in ansible-vault for real playbooks.',
				code: `- name: Enroll hosts with Nokku
  hosts: all
  become: true
  vars:
    nokkud_enroll_token: "${token}"
  tasks:
    - name: Install nokkud
      ansible.builtin.shell: ${installer} | sh
      args:
        creates: /usr/bin/nokkud

    - name: Enroll
      ansible.builtin.command: nokkud enroll
      args:
        creates: /var/lib/nokkud/config.json
      environment:
        NOKKUD_ENROLL_TOKEN: "{{ nokkud_enroll_token }}"${selfHosted ? `\n        NOKKUD_API_URL: "${location.origin}"` : ''}${pin ? `\n        NOKKUD_API_PIN: "${pin}"` : ''}
      no_log: true
      notify: Restart nokkud

    - name: Keep nokkud running
      ansible.builtin.systemd_service:
        name: nokkud
        state: started
        enabled: true

  handlers:
    - name: Restart nokkud
      ansible.builtin.systemd_service:
        name: nokkud
        state: restarted`
			},
			{
				value: 'cloud-init',
				label: 'cloud-init',
				language: 'yaml',
				hint: 'User data is readable from the instance metadata, so use a short expiry and a use limit.',
				code: `#cloud-config
runcmd:
  - ${installer} | sh
  - NOKKUD_ENROLL_TOKEN='${token}' ${apiEnv}nokkud enroll
  - systemctl restart nokkud`
			},
			{
				value: 'container',
				label: 'Container',
				language: 'bash',
				hint: 'The container enrolls itself on start and is reached through the relay, no port to open. An ephemeral token removes it again when it stops.',
				code: [
					'docker run -d --hostname alice \\',
					...envFlags(token).map((e) => `  -e ${e} \\`),
					'  ghcr.io/nokku-sh/nokkud',
					'ssh dev@alice'
				].join('\n')
			}
		];
	}
</script>

<TokenSheet
	bind:open
	kind={JoinTokenKind.ENROLL}
	title="Enroll daemons"
	description="Tokens let new nokkud installs join this workspace. One token can enroll a whole fleet."
	icon={Rocket}
	labelPlaceholder="ansible prod-eu"
>
	{#snippet reveal(secret)}
		<div class="flex items-center gap-2 rounded-lg border bg-muted/40 px-3 py-2">
			<span class="shrink-0 text-xs text-muted-foreground">Token</span>
			<CopyText value={secret} mono class="text-sm" />
		</div>

		<Tabs.Root value="host" class="gap-2">
			<Tabs.List variant="line" class="w-full justify-start">
				{#each snippets(secret) as s (s.value)}
					<Tabs.Trigger value={s.value} class="flex-none">{s.label}</Tabs.Trigger>
				{/each}
			</Tabs.List>
			{#each snippets(secret) as s (s.value)}
				<Tabs.Content value={s.value} class="flex flex-col gap-2">
					<CodeSnippet code={s.code} language={s.language} />
					<p class="text-xs text-muted-foreground">{s.hint}</p>
				</Tabs.Content>
			{/each}
		</Tabs.Root>

		{#if selfHosted}
			<Alert.Root variant="info">
				<Info />
				<Alert.Description>
					Self-hosted: the commands point nokkud at {location.origin} through NOKKUD_API_URL.
					{#if pin}NOKKUD_API_PIN lets it trust the private CA of this server.{/if}
				</Alert.Description>
			</Alert.Root>
		{/if}
	{/snippet}
</TokenSheet>
