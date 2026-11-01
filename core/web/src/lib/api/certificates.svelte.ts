import {
	CertificateService,
	type CertificateAuthority
} from '#lib/gen/nokku/v1/certificates_pb.js';
import { timestampDate, type Timestamp } from '@bufbuild/protobuf/wkt';
import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '#lib/query/index.js';
import { usePatch } from './mask';

// A server set up with nk sync only learns a new CA key from nk sync. A sync while
// the old key still counts writes both, and the server can't drop one on a date.
export function manualKeyState(
	authority: Pick<CertificateAuthority, 'rotatedAt' | 'previousTrustedUntil'> | undefined,
	syncedAt: Timestamp | undefined
): { rotated: boolean; oldKeyUntil?: Timestamp } {
	const rotatedAt = authority?.rotatedAt;
	const until = authority?.previousTrustedUntil;
	if (!syncedAt) return { rotated: false };
	if (rotatedAt && timestampDate(rotatedAt) > timestampDate(syncedAt)) return { rotated: true };
	if (until && timestampDate(syncedAt) < timestampDate(until)) {
		return { rotated: false, oldKeyUntil: until };
	}
	return { rotated: false };
}

// A workspace has one CA, so nothing here takes an id.
export const ca = {
	get: () =>
		useQuery(CertificateService.method.getCertificateAuthority, {}, () => ({
			select: (res) => res.certificateAuthority
		})),
	update: () => usePatch(CertificateService.method.updateCertificateAuthority),
	rollover: () =>
		useMutation(CertificateService.method.rolloverCertificateAuthority, {
			onSuccess: () => toast.success('New keys are in place')
		})
};
