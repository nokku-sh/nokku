import { CertificateService } from '#lib/gen/nokku/v1/certificates_pb.js';
import { timestampDate, type Timestamp } from '@bufbuild/protobuf/wkt';
import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '#lib/query/index.js';
import { usePatch } from './mask';

// A server set up with nk sync learns a new CA key only from nk sync.
export function missedRollover(
	rotatedAt: Timestamp | undefined,
	syncedAt: Timestamp | undefined
): boolean {
	return !!rotatedAt && !!syncedAt && timestampDate(rotatedAt) > timestampDate(syncedAt);
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
