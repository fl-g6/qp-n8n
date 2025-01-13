import { Get, Post, RestController } from '@/decorators';
import { issueCookie, resolveJwt } from '@/auth/jwt';
import { AUTH_COOKIE_NAME, UM_FIX_INSTRUCTION } from '@/constants';
import { Response } from 'express';
import type { User } from '@db/entities/User';
import type { PostHogClient } from '@/posthog';

import { QpJwtRequest } from '@/middlewares/external-jwt-auth';
import { UserService } from '@/services/user.service';
import { UserRepository } from '@/databases/repositories/user.repository';
import { RoleRepository } from '@/databases/repositories/role.repository';
import { PublicUser } from '@/interfaces';
import { AuthError } from '@/errors/response-errors/auth.error';
import { Service } from 'typedi';
import { License } from '@/License';
import { MfaService } from '@/Mfa/mfa.service';
import { InternalHooks } from '@/InternalHooks';

export type TenantRequest = QpJwtRequest<
	{},
	{},
	{
		//product_id: string;
		service_id: string;
	}
>;

@RestController('/quickplay')
export class QuickplayController {
	constructor(
		private readonly userService: UserService,
		private readonly userRepository: UserRepository,
		private readonly roleRepository: RoleRepository,
	) {}

	@Get('/check')
	async check(req: QpJwtRequest): Promise<object> {
		// Manually check the existing cookie.
		// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
		const cookieContents = req.cookies?.[AUTH_COOKIE_NAME] as string | undefined;

		const result = {
			jwt: req.jwt,
			env: process.env,
			headers: req.headers,
		};

		if (cookieContents) {
			const user: User = await resolveJwt(cookieContents);
			return {
				cookieUser: user,
				...result,
			};
		}

		return result;
	}

	@Post('/tenant')
	async tenant(req: TenantRequest, res: Response): Promise<PublicUser> {
		if (!req.jwt) throw new AuthError('Token not found');

		const { service_id } = req.body;
		if (!service_id) throw new Error('service_id is required');
		const service_id_jwt = req.jwt.gcip.x_qp_entitlements.service_id;
		if (service_id_jwt != service_id) throw new Error('ServiceId selected doesnt match!');

		//const product = products.find((i) => i.product_id === product_id);
		const workflow = req.jwt.gcip.x_qp_entitlements.workflow;

		if (!workflow) throw new Error('workflow is not found in JWT');

		const email = `${workflow}@qp.qp`;
		const user = await this.userRepository.findOne({
			relations: ['globalRole'],
			where: { email },
		});
		if (!user) throw new Error(`There is no user with email ${email}`);
		if (!user.password || user.disabled) throw new Error('User has no password or disabled');
		await issueCookie(res, user);
		return this.userService.toPublic(user);
	}

	@Post('/login-as-owner')
	async loginAsOwner(req: TenantRequest, res: Response): Promise<PublicUser> {
		if (!req.jwt) throw new AuthError('Token not found');

		//Validate the role for admin privileges
		const api_roles = req.jwt.gcip.x_qp_entitlements.api_roles;
		const adminSupportedRoles: string[] = ['cms_admin', 'admin'];
		const isAdmin: string[] = api_roles.filter((item) => adminSupportedRoles.includes(item));

		if (isAdmin.length == 0) throw new AuthError('Infufficient permissions');

		const ownerGlobalRole = await this.roleRepository.findRole('global', 'owner');

		if (!ownerGlobalRole) {
			throw new Error(`Failed to find globel owner role.`);
		}

		const owner =
			ownerGlobalRole &&
			(await this.userRepository.findOneBy({ globalRoleId: ownerGlobalRole.id }));

		if (!owner) {
			throw new Error(`Failed to find owner. ${UM_FIX_INSTRUCTION}`);
		}

		if (!owner.password || owner.disabled) throw new Error('Owner has no password or disabled');

		await issueCookie(res, owner);
		return this.userService.toPublic(owner);
	}
}
