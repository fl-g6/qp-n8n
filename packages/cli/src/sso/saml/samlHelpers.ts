<<<<<<< HEAD
import { Container } from 'typedi';
import config from '@/config';
import * as Db from '@/Db';
import { AuthIdentity } from '@db/entities/AuthIdentity';
import { User } from '@db/entities/User';
import { RoleRepository } from '@db/repositories';
import { License } from '@/License';
import { AuthError, InternalServerError } from '@/ResponseHelper';
import { hashPassword, isUserManagementEnabled } from '@/UserManagement/UserManagementHelper';
=======
import config from '@/config';
import * as Db from '@/Db';
import { AuthIdentity } from '../../databases/entities/AuthIdentity';
import { User } from '../../databases/entities/User';
import { getLicense } from '../../License';
import { AuthError } from '../../ResponseHelper';
import { hashPassword, isUserManagementEnabled } from '../../UserManagement/UserManagementHelper';
>>>>>>> master
import type { SamlPreferences } from './types/samlPreferences';
import type { SamlUserAttributes } from './types/samlUserAttributes';
import type { FlowResult } from 'samlify/types/src/flow';
import type { SamlAttributeMapping } from './types/samlAttributeMapping';
<<<<<<< HEAD
import { SAML_LOGIN_ENABLED, SAML_LOGIN_LABEL } from './constants';
import {
	getCurrentAuthenticationMethod,
=======
import { SAML_ENTERPRISE_FEATURE_ENABLED, SAML_LOGIN_ENABLED, SAML_LOGIN_LABEL } from './constants';
import {
>>>>>>> master
	isEmailCurrentAuthenticationMethod,
	isSamlCurrentAuthenticationMethod,
	setCurrentAuthenticationMethod,
} from '../ssoHelpers';
<<<<<<< HEAD
import { getServiceProviderConfigTestReturnUrl } from './serviceProvider.ee';
import type { SamlConfiguration } from './types/requests';
=======
>>>>>>> master
/**
 *  Check whether the SAML feature is licensed and enabled in the instance
 */
export function isSamlLoginEnabled(): boolean {
	return config.getEnv(SAML_LOGIN_ENABLED);
}

export function getSamlLoginLabel(): string {
	return config.getEnv(SAML_LOGIN_LABEL);
}

// can only toggle between email and saml, not directly to e.g. ldap
<<<<<<< HEAD
export async function setSamlLoginEnabled(enabled: boolean): Promise<void> {
	if (isEmailCurrentAuthenticationMethod() || isSamlCurrentAuthenticationMethod()) {
		if (enabled) {
			config.set(SAML_LOGIN_ENABLED, true);
			await setCurrentAuthenticationMethod('saml');
		} else if (!enabled) {
			config.set(SAML_LOGIN_ENABLED, false);
			await setCurrentAuthenticationMethod('email');
		}
	} else {
		throw new InternalServerError(
			`Cannot switch SAML login enabled state when an authentication method other than email or saml is active (current: ${getCurrentAuthenticationMethod()})`,
		);
=======
export function setSamlLoginEnabled(enabled: boolean): void {
	if (enabled) {
		if (isEmailCurrentAuthenticationMethod()) {
			config.set(SAML_LOGIN_ENABLED, true);
			setCurrentAuthenticationMethod('saml');
		}
	} else {
		config.set(SAML_LOGIN_ENABLED, false);
		setCurrentAuthenticationMethod('email');
>>>>>>> master
	}
}

export function setSamlLoginLabel(label: string): void {
	config.set(SAML_LOGIN_LABEL, label);
}

export function isSamlLicensed(): boolean {
<<<<<<< HEAD
	const license = Container.get(License);
	return isUserManagementEnabled() && license.isSamlEnabled();
=======
	const license = getLicense();
	return (
		isUserManagementEnabled() &&
		(license.isSamlEnabled() || config.getEnv(SAML_ENTERPRISE_FEATURE_ENABLED))
	);
>>>>>>> master
}

export function isSamlLicensedAndEnabled(): boolean {
	return isSamlLoginEnabled() && isSamlLicensed() && isSamlCurrentAuthenticationMethod();
}

export const isSamlPreferences = (candidate: unknown): candidate is SamlPreferences => {
	const o = candidate as SamlPreferences;
	return (
		typeof o === 'object' &&
		typeof o.metadata === 'string' &&
		typeof o.mapping === 'object' &&
		o.mapping !== null &&
		o.loginEnabled !== undefined
	);
};

export function generatePassword(): string {
	const length = 18;
	const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
	const charsetNoNumbers = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
	const randomNumber = Math.floor(Math.random() * 10);
	const randomUpper = charset.charAt(Math.floor(Math.random() * charsetNoNumbers.length));
	const randomNumberPosition = Math.floor(Math.random() * length);
	const randomUpperPosition = Math.floor(Math.random() * length);
	let password = '';
	for (let i = 0, n = charset.length; i < length; ++i) {
		password += charset.charAt(Math.floor(Math.random() * n));
	}
	password =
		password.substring(0, randomNumberPosition) +
		randomNumber.toString() +
		password.substring(randomNumberPosition);
	password =
		password.substring(0, randomUpperPosition) +
		randomUpper +
		password.substring(randomUpperPosition);
	return password;
}

export async function createUserFromSamlAttributes(attributes: SamlUserAttributes): Promise<User> {
	const user = new User();
	const authIdentity = new AuthIdentity();
	user.email = attributes.email;
	user.firstName = attributes.firstName;
	user.lastName = attributes.lastName;
<<<<<<< HEAD
	user.globalRole = await Container.get(RoleRepository).findGlobalMemberRoleOrFail();
=======
	user.globalRole = await Db.collections.Role.findOneOrFail({
		where: { name: 'member', scope: 'global' },
	});
>>>>>>> master
	// generates a password that is not used or known to the user
	user.password = await hashPassword(generatePassword());
	authIdentity.providerId = attributes.userPrincipalName;
	authIdentity.providerType = 'saml';
	authIdentity.user = user;
	const resultAuthIdentity = await Db.collections.AuthIdentity.save(authIdentity);
	if (!resultAuthIdentity) throw new AuthError('Could not create AuthIdentity');
	user.authIdentities = [authIdentity];
	const resultUser = await Db.collections.User.save(user);
	if (!resultUser) throw new AuthError('Could not create User');
	return resultUser;
}

export async function updateUserFromSamlAttributes(
	user: User,
	attributes: SamlUserAttributes,
): Promise<User> {
	if (!attributes.email) throw new AuthError('Email is required to update user');
	if (!user) throw new AuthError('User not found');
	let samlAuthIdentity = user?.authIdentities.find((e) => e.providerType === 'saml');
	if (!samlAuthIdentity) {
		samlAuthIdentity = new AuthIdentity();
		samlAuthIdentity.providerId = attributes.userPrincipalName;
		samlAuthIdentity.providerType = 'saml';
		samlAuthIdentity.user = user;
		user.authIdentities.push(samlAuthIdentity);
	} else {
		samlAuthIdentity.providerId = attributes.userPrincipalName;
	}
	await Db.collections.AuthIdentity.save(samlAuthIdentity);
	user.firstName = attributes.firstName;
	user.lastName = attributes.lastName;
	const resultUser = await Db.collections.User.save(user);
	if (!resultUser) throw new AuthError('Could not create User');
	return resultUser;
}

type GetMappedSamlReturn = {
	attributes: SamlUserAttributes | undefined;
	missingAttributes: string[];
};

export function getMappedSamlAttributesFromFlowResult(
	flowResult: FlowResult,
	attributeMapping: SamlAttributeMapping,
): GetMappedSamlReturn {
	const result: GetMappedSamlReturn = {
		attributes: undefined,
		missingAttributes: [] as string[],
	};
	// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
	if (flowResult?.extract?.attributes) {
		// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
		const attributes = flowResult.extract.attributes as { [key: string]: string };
		// TODO:SAML: fetch mapped attributes from flowResult.extract.attributes and create or login user
		const email = attributes[attributeMapping.email];
		const firstName = attributes[attributeMapping.firstName];
		const lastName = attributes[attributeMapping.lastName];
		const userPrincipalName = attributes[attributeMapping.userPrincipalName];

		result.attributes = {
			email,
			firstName,
			lastName,
			userPrincipalName,
		};
		if (!email) result.missingAttributes.push(attributeMapping.email);
		if (!userPrincipalName) result.missingAttributes.push(attributeMapping.userPrincipalName);
		if (!firstName) result.missingAttributes.push(attributeMapping.firstName);
		if (!lastName) result.missingAttributes.push(attributeMapping.lastName);
	}
	return result;
}
<<<<<<< HEAD

export function isConnectionTestRequest(req: SamlConfiguration.AcsRequest): boolean {
	return req.body.RelayState === getServiceProviderConfigTestReturnUrl();
}
=======
>>>>>>> master
