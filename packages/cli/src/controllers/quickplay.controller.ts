import { Response } from 'express';
import { ApplicationError } from 'n8n-workflow';

import { issueCookie, resolveJwt } from '@/auth/jwt';
import { AUTH_COOKIE_NAME, UM_FIX_INSTRUCTION } from '@/constants';
import type { User } from '@/databases/entities/user';
import { ProjectRepository } from '@/databases/repositories/project.repository';
import { UserRepository } from '@/databases/repositories/user.repository';
import { Get, Post, RestController } from '@/decorators';
import { AuthError } from '@/errors/response-errors/auth.error';
import type { PublicUser } from '@/interfaces';
import { QpJwtRequest } from '@/middlewares/external-jwt-auth';
import { UserService } from '@/services/user.service';

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
		private readonly projectRepository: ProjectRepository,
	) {}

	@Get('/check', { skipAuth: true })
	async check(req: QpJwtRequest): Promise<object> {
		// Manually check the existing cookie.
		// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
		const cookieContents = req.cookies?.[AUTH_COOKIE_NAME] as string | undefined;

		const result = {
			// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
			jwt: req.jwt,
			env: process.env,
			// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
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

	//Tenant data authenticate
	// To test - @GlobalScope(['user:read','user:list'])
	@Post('/tenant', { skipAuth: true })
	async tenant(req: TenantRequest, res: Response): Promise<PublicUser> {
		// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
		if (!req.jwt) throw new AuthError('Token not found');

		// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
		const { service_id } = req.body;
		if (!service_id) throw new ApplicationError('service_id is required');
		const service_id_jwt = req.jwt.gcip.x_qp_entitlements.service_id;
		if (service_id_jwt !== service_id)
			throw new ApplicationError('ServiceId selected doesnt match!');

		//const product = products.find((i) => i.product_id === product_id);
		const workflow = req.jwt.gcip.x_qp_entitlements.workflow;

		if (!workflow) throw new ApplicationError('workflow is not found in JWT');

		const email = `${workflow}@qp.qp`;

		// // TODO - Backport Support is not available for old tenants using globalRole
		// const userOld = await this.userRepository.findOne({
		// 	relations: ['globalRole'],
		// 	where: { email },
		// });

		// if (!userOld) {
		// 	console.warn('Using Old tenant approach, change from globalRole to Role');
		// } else {
		// 	//if (!userOld) throw new Error(`There is no user with email ${email}`);
		// 	if (!userOld.password || userOld.disabled)
		// 		throw new Error('User has no password or disabled');
		// 	await issueCookie(res, userOld);
		// 	return this.userService.toPublic(userOld);
		// }

		// Support for new tenants using globalRole
		const user = await this.userRepository.findOne({
			// relations: ['role'],
			where: { email },
		});

		if (!user) throw new ApplicationError(`There is no user with email ${email}`);
		// TODO - Enable once validated
		// if (!user.password || user.disabled) throw new ApplicationError('User has no password or disabled');
		await issueCookie(res, user);
		return await this.userService.toPublic(user);
	}

	@Post('/login-as-owner', { skipAuth: true })
	async loginAsOwner(req: TenantRequest, res: Response): Promise<PublicUser> {
		// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
		if (!req.jwt) throw new AuthError('Token not found');

		//Validate the role for admin privileges
		// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
		const api_roles = req.jwt.gcip.x_qp_entitlements.api_roles;
		const adminSupportedRoles: string[] = ['cms_admin', 'admin'];
		// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
		const isAdmin: string[] = api_roles.filter((item: string) =>
			adminSupportedRoles.includes(item),
		);

		if (isAdmin.length === 0) throw new AuthError('Infufficient permissions');

		const owner = await this.userRepository.findOneBy({
			role: 'global:owner',
		});

		// const owner =
		// ownerGlobalRoleNew &&
		// 	(await this.userRepository.findOneBy({ globalRoleId: ownerGlobalRole.id }));

		if (!owner) {
			throw new ApplicationError(`Failed to find owner. ${UM_FIX_INSTRUCTION}`);
		}

		if (!owner.password || owner.disabled)
			throw new ApplicationError('Owner has no password or disabled');

		await issueCookie(res, owner);
		return await this.userService.toPublic(owner);
	}
}
