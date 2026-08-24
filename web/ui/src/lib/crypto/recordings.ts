export function formatBytes(bytes: number): string {
	if (bytes >= 1 << 30) return `${(bytes / (1 << 30)).toFixed(1)} GiB`;
	if (bytes >= 1 << 20) return `${(bytes / (1 << 20)).toFixed(1)} MiB`;
	if (bytes >= 1 << 10) return `${(bytes / (1 << 10)).toFixed(1)} KiB`;
	return `${bytes} B`;
}
