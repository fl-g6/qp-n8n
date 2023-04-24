<<<<<<< HEAD
import { Container } from 'typedi';
import type { SuperAgentTest } from 'supertest';
import type { User } from '@db/entities/User';
import { setSamlLoginEnabled } from '@/sso/saml/samlHelpers';
import { getCurrentAuthenticationMethod, setCurrentAuthenticationMethod } from '@/sso/ssoHelpers';
import { License } from '@/License';
import { randomEmail, randomName, randomValidPassword } from '../shared/random';
import * as testDb from '../shared/testDb';
import * as utils from '../shared/utils';
import { sampleConfig } from './sampleMetadata';

let owner: User;
let authOwnerAgent: SuperAgentTest;

async function enableSaml(enable: boolean) {
	await setSamlLoginEnabled(enable);
}

beforeAll(async () => {
	Container.get(License).isSamlEnabled = () => true;
	const app = await utils.initTestServer({ endpointGroups: ['me', 'saml'] });
	owner = await testDb.createOwner();
	authOwnerAgent = utils.createAuthAgent(app)(owner);
=======
import express from 'express';

import config from '@/config';
import type { Role } from '@db/entities/Role';
import { randomEmail, randomName, randomValidPassword } from '../shared/random';
import * as testDb from '../shared/testDb';
import type { AuthAgent } from '../shared/types';
import * as utils from '../shared/utils';
import { setSamlLoginEnabled } from '../../../src/sso/saml/samlHelpers';
import { setCurrentAuthenticationMethod } from '../../../src/sso/ssoHelpers';

let app: express.Application;
let globalOwnerRole: Role;
let globalMemberRole: Role;
let authAgent: AuthAgent;

function enableSaml(enable: boolean) {
	setSamlLoginEnabled(enable);
	setCurrentAuthenticationMethod(enable ? 'saml' : 'email');
	config.set('enterprise.features.saml', enable);
}

beforeAll(async () => {
	app = await utils.initTestServer({ endpointGroups: ['me'] });

	globalOwnerRole = await testDb.getGlobalOwnerRole();
	globalMemberRole = await testDb.getGlobalMemberRole();

	authAgent = utils.createAuthAgent(app);
});

beforeEach(async () => {
	await testDb.truncate(['User']);
>>>>>>> master
});

afterAll(async () => {
	await testDb.terminate();
});

<<<<<<< HEAD
describe('Instance owner', () => {
	describe('PATCH /me', () => {
		test('should succeed with valid inputs', async () => {
			await enableSaml(false);
			await authOwnerAgent
				.patch('/me')
				.send({
					email: randomEmail(),
					firstName: randomName(),
					lastName: randomName(),
					password: randomValidPassword(),
				})
				.expect(200);
		});

		test('should throw BadRequestError if email is changed when SAML is enabled', async () => {
			await enableSaml(true);
			await authOwnerAgent
				.patch('/me')
				.send({
					email: randomEmail(),
					firstName: randomName(),
					lastName: randomName(),
				})
				.expect(400, { code: 400, message: 'SAML user may not change their email' });
		});
	});

	describe('PATCH /password', () => {
		test('should throw BadRequestError if password is changed when SAML is enabled', async () => {
			await enableSaml(true);
			await authOwnerAgent
				.patch('/me/password')
				.send({
					password: randomValidPassword(),
				})
				.expect(400, {
					code: 400,
					message: 'With SAML enabled, users need to use their SAML provider to change passwords',
				});
		});
	});

	describe('POST /sso/saml/config', () => {
		test('should post saml config', async () => {
			await authOwnerAgent
				.post('/sso/saml/config')
				.send({
					...sampleConfig,
					loginEnabled: true,
				})
				.expect(200);
			expect(getCurrentAuthenticationMethod()).toBe('saml');
		});
	});

	describe('POST /sso/saml/config/toggle', () => {
		test('should toggle saml as default authentication method', async () => {
			await enableSaml(true);
			expect(getCurrentAuthenticationMethod()).toBe('saml');

			await authOwnerAgent
				.post('/sso/saml/config/toggle')
				.send({
					loginEnabled: false,
				})
				.expect(200);
			expect(getCurrentAuthenticationMethod()).toBe('email');

			await authOwnerAgent
				.post('/sso/saml/config/toggle')
				.send({
					loginEnabled: true,
				})
				.expect(200);
			expect(getCurrentAuthenticationMethod()).toBe('saml');
		});
	});

	describe('POST /sso/saml/config/toggle', () => {
		test('should fail enable saml if default authentication is not email', async () => {
			await enableSaml(true);

			await authOwnerAgent
				.post('/sso/saml/config/toggle')
				.send({
					loginEnabled: false,
				})
				.expect(200);
			expect(getCurrentAuthenticationMethod()).toBe('email');

			await setCurrentAuthenticationMethod('ldap');
			expect(getCurrentAuthenticationMethod()).toBe('ldap');

			await authOwnerAgent
				.post('/sso/saml/config/toggle')
				.send({
					loginEnabled: true,
				})
				.expect(500);

			expect(getCurrentAuthenticationMethod()).toBe('ldap');
		});
=======
describe('Owner shell', () => {
	test('PATCH /me should succeed with valid inputs', async () => {
		const ownerShell = await testDb.createUserShell(globalOwnerRole);
		const authOwnerShellAgent = authAgent(ownerShell);
		const response = await authOwnerShellAgent.patch('/me').send({
			email: randomEmail(),
			firstName: randomName(),
			lastName: randomName(),
			password: randomValidPassword(),
		});
		expect(response.statusCode).toBe(200);
	});

	test('PATCH /me should throw BadRequestError if email is changed when SAML is enabled', async () => {
		enableSaml(true);
		const ownerShell = await testDb.createUserShell(globalOwnerRole);
		const authOwnerShellAgent = authAgent(ownerShell);
		const response = await authOwnerShellAgent.patch('/me').send({
			email: randomEmail(),
			firstName: randomName(),
			lastName: randomName(),
		});
		expect(response.statusCode).toBe(400);
		expect(response.body.message).toContain('SAML');
		enableSaml(false);
	});

	test('PATCH /password should throw BadRequestError if password is changed when SAML is enabled', async () => {
		enableSaml(true);
		const ownerShell = await testDb.createUserShell(globalOwnerRole);
		const authOwnerShellAgent = authAgent(ownerShell);
		const response = await authOwnerShellAgent.patch('/me/password').send({
			password: randomValidPassword(),
		});
		expect(response.statusCode).toBe(400);
		expect(response.body.message).toContain('SAML');
		enableSaml(false);
>>>>>>> master
	});
});
