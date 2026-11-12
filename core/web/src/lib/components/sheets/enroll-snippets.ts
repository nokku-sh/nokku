// The installer needs root. Ansible and cloud-init already run as root.
const installer = 'curl -fsSL https://get.nokku.sh/nokkud';

/** The ways to install nokkud and enroll with a token, one per tab of the enroll sheet. */
export function enrollSnippets(token: string) {
	// nokkud knows no address by itself, every workspace has its own.
	const apiEnv = `NOKKUD_API_URL=${location.origin} `;
	const envFlags = [`NOKKUD_ENROLL_TOKEN='${token}'`, `NOKKUD_API_URL=${location.origin}`];
	return [
		{
			value: 'host',
			label: 'One server',
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
        creates: /var/lib/nokkud/ssh_host_ecdsa_key
      environment:
        NOKKUD_ENROLL_TOKEN: "{{ nokkud_enroll_token }}"
        NOKKUD_API_URL: "${location.origin}"
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
				...envFlags.map((e) => `  -e ${e} \\`),
				'  ghcr.io/nokku-sh/nokkud',
				'ssh dev@alice'
			].join('\n')
		}
	];
}
