import {
	CertificateService,
	SignSSHCertificateRequest_CertificateType
} from '$lib/gen/nokku/v1/certificates_pb';
import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '$lib/query';
import { workspaceID } from '$lib/store.svelte';

export const sign = {
	user: () =>
		useMutation(CertificateService.method.signSSHCertificate, {
			onSuccess: () => toast.success('Certificate signed'),
			transform: (variables) => ({
				...variables,
				workspaceId: workspaceID.current,
				type: SignSSHCertificateRequest_CertificateType.USER
			})
		}),
	host: () =>
		useMutation(CertificateService.method.signSSHCertificate, {
			onSuccess: () => toast.success('Host certificate signed'),
			transform: (variables) => ({
				...variables,
				workspaceId: workspaceID.current,
				type: SignSSHCertificateRequest_CertificateType.HOST
			})
		}),
	x509: () =>
		useMutation(CertificateService.method.signX509Certificate, {
			onSuccess: () => toast.success('Certificate signed'),
			transform: (variables) => ({
				...variables,
				workspaceId: workspaceID.current
			})
		})
};

export const ca = {
	// Queries
	get: (id?: string) =>
		useQuery(
			CertificateService.method.getCertificateAuthority,
			{ id },
			{ enabled: !!workspaceID.current && !!id, select: (res) => res.certificateAuthority }
		),
	list: () =>
		useQuery(
			CertificateService.method.listCertificateAuthorities,
			{ workspaceId: workspaceID.current },
			{ enabled: !!workspaceID.current, select: (res) => res.certificateAuthorities }
		),

	// Mutations
	create: () =>
		useMutation(CertificateService.method.createCertificateAuthority, {
			onSuccess: () => toast.success('Certificate Authority created!'),
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		}),
	update: () =>
		useMutation(CertificateService.method.updateCertificateAuthority, {
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		}),
	delete: () =>
		useMutation(CertificateService.method.deleteCertificateAuthority, {
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		}),
	rollover: () =>
		useMutation(CertificateService.method.rolloverCertificateAuthority, {
			onSuccess: (data) => {
				if (!data.certificateAuthority) {
					toast.success('Rollover skipped');
					return;
				}
				toast.success('Certificate Authority rolled over');
			},
			transform: (variables) => ({ ...variables, workspaceId: workspaceID.current })
		})
};
