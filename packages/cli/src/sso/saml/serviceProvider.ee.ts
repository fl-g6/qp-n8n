/* eslint-disable @typescript-eslint/naming-convention */
import { getInstanceBaseUrl } from '@/UserManagement/UserManagementHelper';
import type { ServiceProviderInstance } from 'samlify';
import { ServiceProvider } from 'samlify';
import { SamlUrls } from './constants';
import type { SamlPreferences } from './types/samlPreferences';

let serviceProviderInstance: ServiceProviderInstance | undefined;

<<<<<<< HEAD
export function getServiceProviderEntityId(): string {
	return getInstanceBaseUrl() + SamlUrls.restMetadata;
}

export function getServiceProviderReturnUrl(): string {
	return getInstanceBaseUrl() + SamlUrls.restAcs;
}

export function getServiceProviderConfigTestReturnUrl(): string {
	return getInstanceBaseUrl() + SamlUrls.configTestReturn;
}

=======
>>>>>>> master
// TODO:SAML: make these configurable for the end user
export function getServiceProviderInstance(prefs: SamlPreferences): ServiceProviderInstance {
	if (serviceProviderInstance === undefined) {
		serviceProviderInstance = ServiceProvider({
<<<<<<< HEAD
			entityID: getServiceProviderEntityId(),
=======
			entityID: getInstanceBaseUrl() + SamlUrls.restMetadata,
>>>>>>> master
			authnRequestsSigned: prefs.authnRequestsSigned,
			wantAssertionsSigned: prefs.wantAssertionsSigned,
			wantMessageSigned: prefs.wantMessageSigned,
			signatureConfig: prefs.signatureConfig,
<<<<<<< HEAD
			relayState: prefs.relayState,
=======
>>>>>>> master
			nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
			assertionConsumerService: [
				{
					isDefault: prefs.acsBinding === 'post',
					Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
<<<<<<< HEAD
					Location: getServiceProviderReturnUrl(),
=======
					Location: getInstanceBaseUrl() + SamlUrls.restAcs,
>>>>>>> master
				},
				{
					isDefault: prefs.acsBinding === 'redirect',
					Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-REDIRECT',
<<<<<<< HEAD
					Location: getServiceProviderReturnUrl(),
=======
					Location: getInstanceBaseUrl() + SamlUrls.restAcs,
>>>>>>> master
				},
			],
		});
	}

	return serviceProviderInstance;
}
