import {
	UserRepository,
	RoleRepository,
	ProjectRepository,
	ProjectRelationRepository,
	generateNanoId,
} from '@n8n/db';
import { Post, RestController } from '@n8n/decorators';
import { PROJECT_OWNER_ROLE_SLUG } from '@n8n/permissions';
import { GlobalConfig } from '@n8n/config';
import { Logger } from '@n8n/backend-common';
import { Response } from 'express';

import { AuthService } from '@/auth/auth.service';
import { BadRequestError } from '@/errors/response-errors/bad-request.error';
import { AuthError } from '@/errors/response-errors/auth.error';
import { PasswordUtility } from '@/services/password.utility';
import { AuthlessRequest } from '@/requests';
import { NotFoundError } from '@/errors/response-errors/not-found.error';

/**
 * 外部认证控制器 - 用于后台管理系统的单点登录 (SSO)
 */
@RestController('/external-auth')
export class ExternalAuthController {
	// Token 验证缓存 (token -> 验证结果) - 5分钟过期
	private tokenCache = new Map<string, { data: any; expireAt: number }>();

	constructor(
		private readonly userRepository: UserRepository,
		private readonly roleRepository: RoleRepository,
		private readonly projectRepository: ProjectRepository,
		private readonly projectRelationRepository: ProjectRelationRepository,
		private readonly authService: AuthService,
		private readonly passwordUtility: PasswordUtility,
		private readonly globalConfig: GlobalConfig,
		private readonly logger: Logger,
	) {
		this.logger.info('ExternalAuthController 初始化', {
			useMockBackend: this.globalConfig.externalAuth.useMockBackend,
			hasSecret: !!this.globalConfig.externalAuth.secret,
		});
	}

	/**
	 * 外部系统登录接口 - 通过 userId 查找用户并签发 JWT Cookie
	 */
	@Post('/login', { skipAuth: true })
	async externalLogin(req: AuthlessRequest, res: Response) {
		// 1. 获取请求参数：用户标识符和 token
		const payload = req.body as {
			userIdentifier?: string;
			token?: string; // 使用 backend token 验证
		};
		const { userIdentifier, token: backendToken } = payload;

		// 2. 验证 token (使用缓存避免重复验证)
		if (!backendToken) {
			throw new BadRequestError('token is required');
		}

		// 检查缓存
		const cached = this.tokenCache.get(backendToken);
		if (!cached || cached.expireAt < Date.now()) {
			// 缓存不存在或已过期,需要验证
			try {
				const result = await this.verifyBackendToken(req, res);
				// 缓存验证结果 5分钟
				this.tokenCache.set(backendToken, {
					data: result,
					expireAt: Date.now() + 5 * 60 * 1000,
				});
			} catch (error) {
				throw new AuthError('Invalid token');
			}
		}
		// 使用缓存,不再重复验证

		// 3. 检查用户标识符是否存在
		if (!userIdentifier) {
			throw new BadRequestError('userIdentifier is required');
		}

		// 4. 格式化邮箱地址（如果不包含@则添加@n8n.local后缀）
		const emailIdentifier = userIdentifier?.includes('@')
			? userIdentifier
			: `${userIdentifier}@n8n.local`;

		// 5. 从数据库中查找用户
		const user = await this.userRepository.findOne({
			where: { email: emailIdentifier },
			relations: ['role'],
		});

		// 6. 验证用户是否存在
		if (!user) {
			throw new AuthError('User not found. Please create the user first.');
		}

		// 7. 验证用户是否已激活（是否设置了密码）
		if (!user.password) {
			throw new AuthError('User is not activated');
		}

		// 8. 签发 JWT Token
		const token = this.authService.issueJWT(user, false, req.browserId);

		// 9. 设置认证 Cookie
		const cookieOptions = 'HttpOnly; SameSite=Lax; Max-Age=604800; Path=/';

		// 10. 设置认证 Cookie
		res.setHeader('Set-Cookie', `n8n-auth=${token}; ${cookieOptions}`);

		// 11. 返回登录成功响应
		res.status(200).json({
			success: true,
			user: {
				id: user.id,
				email: user.email,
				firstName: user.firstName,
				lastName: user.lastName,
			},
		});
	}

	/**
	 * 创建外部用户接口 - 在 n8n 中创建用户及其 Personal Project
	 */
	@Post('/create-user', { skipAuth: true })
	async createExternalUser(req: AuthlessRequest, _res: Response) {
		// 1. 获取请求参数：用户ID、姓名和 token
		const payload = req.body as {
			userId?: string;
			firstName?: string;
			lastName?: string;
			token?: string; // 使用 backend token 验证
		};
		const { userId, firstName, lastName, token: backendToken } = payload;

		// 2. 验证 token (使用缓存避免重复验证)
		if (!backendToken) {
			throw new BadRequestError('token is required');
		}

		// 检查缓存
		const cached = this.tokenCache.get(backendToken);
		if (!cached || cached.expireAt < Date.now()) {
			// 缓存不存在或已过期,需要验证
			try {
				const result = await this.verifyBackendToken(req, _res);
				// 缓存验证结果 5分钟
				this.tokenCache.set(backendToken, {
					data: result,
					expireAt: Date.now() + 5 * 60 * 1000,
				});
			} catch (error) {
				throw new AuthError('Invalid token');
			}
		}
		// 使用缓存,不再重复验证

		// 3. 检查 userId 是否存在
		if (!userId) {
			throw new BadRequestError('userId is required');
		}

		// 4. 格式化邮箱地址（如果不包含@则添加@n8n.local后缀）
		const emailAddress = userId?.includes('@') ? userId : `${userId}@n8n.local`;

		// 5. 检查用户是否已存在
		const existingUser = await this.userRepository.findOne({
			where: { email: emailAddress },
		});

		// 6. 如果用户已存在，直接返回成功
		if (existingUser) {
			const userWithRole = await this.userRepository.findOne({
				where: { email: emailAddress },
				relations: ['role'],
			});

			return {
				success: true,
				message: 'User already exists',
				role: userWithRole?.role?.slug || 'unknown',
				user: {
					id: existingUser.id,
					email: existingUser.email,
					userId: userId,
				},
			};
		}

		// 7. 创建新用户对象
		const newUser = this.userRepository.create({
			email: emailAddress,
			firstName: firstName || 'User',
			lastName: lastName || userId?.substring(0, 8) || 'ID',
			password: await this.hashDummyPassword(),
		});

		// 8. 分配角色（所有新增用户都是管理员）
		const roleSlug = 'global:owner';
		const userRole = await this.roleRepository.findOne({ where: { slug: roleSlug } });

		if (userRole) {
			newUser.role = userRole;
		}

		// 11. 保存用户到数据库
		const savedUser = await this.userRepository.save(newUser);

		// 12. 生成个人项目ID和名称
		const projectId = generateNanoId();
		const projectName = savedUser.createPersonalProjectName();

		// 13. 创建个人项目
		const personalProject = this.projectRepository.create({
			id: projectId,
			type: 'personal',
			name: projectName,
		});

		// 14. 保存个人项目到数据库
		await this.projectRepository.save(personalProject);

		// 15. 创建项目关联关系（用户作为项目所有者）
		const projectRelation = this.projectRelationRepository.create({
			projectId: projectId,
			userId: savedUser.id,
			role: { slug: PROJECT_OWNER_ROLE_SLUG },
		});

		// 16. 保存项目关联关系
		await this.projectRelationRepository.save(projectRelation);

		// 16. 返回创建成功响应
		return {
			success: true,
			message: 'User created successfully as owner',
			role: roleSlug,
			user: {
				id: savedUser.id,
				email: savedUser.email,
				firstName: savedUser.firstName,
				lastName: savedUser.lastName,
			},
		};
	}

	private async hashDummyPassword(): Promise<string> {
		const crypto = await import('crypto');
		const randomPassword = crypto.randomBytes(32).toString('hex');
		return await this.passwordUtility.hash(randomPassword);
	}

	/**
	 * 删除外部用户接口 - 同步删除 n8n 中的用户
	 */
	@Post('/delete-user', { skipAuth: true })
	async deleteExternalUser(req: AuthlessRequest, _res: Response) {
		// 1. 获取请求参数：用户ID和认证密钥
		const payload = req.body as { userId?: string; authSecret?: string };
		const { userId, authSecret } = payload;

		// 2. 验证认证密钥
		const expectedSecret = this.globalConfig.externalAuth.secret;
		if (authSecret !== expectedSecret) {
			throw new AuthError('Invalid auth secret');
		}

		// 3. 检查 userId 是否存在
		if (!userId) {
			throw new BadRequestError('userId is required');
		}

		// 4. 格式化邮箱地址（如果不包含@则添加@n8n.local后缀）
		const emailAddress = userId?.includes('@') ? userId : `${userId}@n8n.local`;

		// 5. 从数据库中查找用户
		const user = await this.userRepository.findOne({
			where: { email: emailAddress },
		});

		// 6. 如果用户不存在，直接返回成功（幂等性）
		if (!user) {
			return {
				success: true,
				message: 'User not found (already deleted or never existed)',
			};
		}

		// 7. 删除用户（会级联删除相关数据）
		await this.userRepository.remove(user);

		// 8. 返回删除成功响应
		return {
			success: true,
			message: 'User deleted successfully',
		};
	}

	/**
	 * 获取用户权限接口 - 查询用户的全局角色和项目角色
	 *
	 * 权限类型说明：
	 * 1. 全局角色 (Global Role):
	 *    - global:owner  : 实例拥有者，拥有最高权限
	 *    - global:admin  : 全局管理员，可以管理用户和全局设置
	 *    - global:member : 普通成员，基础权限
	 *
	 * 2. 项目角色 (Project Role):
	 *    - project:owner  : 项目所有者（仅用于个人项目）
	 *    - project:admin  : 项目管理员，可以管理项目设置、成员、工作流、凭证
	 *    - project:editor : 项目编辑者，可以创建、编辑、删除工作流和凭证
	 *    - project:viewer : 项目查看者，只读访问工作流和凭证
	 *
	 * 注意：凭证(Credential)和工作流(Workflow)的权限是通过项目(Project)来管理的
	 */
	@Post('/get-permissions', { skipAuth: true })
	async getPermissions(req: AuthlessRequest, _res: Response) {
		// 1. 获取请求参数：用户ID和认证密钥
		const payload = req.body as { userId?: string; authSecret?: string };
		const { userId, authSecret } = payload;

		// 2. 验证认证密钥
		const expectedSecret = this.globalConfig.externalAuth.secret;
		if (authSecret !== expectedSecret) {
			throw new AuthError('Invalid auth secret');
		}

		// 3. 检查 userId 是否存在
		if (!userId) {
			throw new BadRequestError('userId is required');
		}

		// 4. 格式化邮箱地址
		const emailAddress = userId?.includes('@') ? userId : `${userId}@n8n.local`;

		// 5. 查找用户及其全局角色
		const user = await this.userRepository.findOne({
			where: { email: emailAddress },
			relations: ['role'],
		});

		if (!user) {
			throw new NotFoundError('User not found');
		}

		// 6. 查找用户的项目关系
		const projectRelations = await this.projectRelationRepository.find({
			where: { userId: user.id },
			relations: ['project', 'role'],
		});

		// 7. 构建项目权限列表
		const projects = projectRelations.map((pr) => ({
			projectId: pr.projectId,
			projectName: pr.project.name,
			projectType: pr.project.type,
			role: pr.role.slug,
		}));

		// 8. 返回权限信息
		return {
			success: true,
			user: {
				id: user.id,
				email: user.email,
				firstName: user.firstName,
				lastName: user.lastName,
				globalRole: user.role.slug,
			},
			permissions: {
				globalRole: user.role.slug,
				projects,
			},
		};
	}

	/**
	 * 验证后台系统 Token 接口 - 代理调用后台系统的 token 验证接口（解决跨域问题）
	 */
	@Post('/verify-backend-token', { skipAuth: true })
	async verifyBackendToken(req: AuthlessRequest, _res: Response) {
		// 1. 获取请求参数：token
		const payload = req.body as { token?: string };
		const { token } = payload;
		// 2. 检查 token 是否存在
		if (!token) {
			throw new BadRequestError('token is required');
		}

		// 3. 调用后台系统的 token 验证接口
		// 测试模式：如果设置了 USE_MOCK_BACKEND=true，则使用本地模拟接口
		let verifyUrl: string;
		if (this.globalConfig.externalAuth.useMockBackend) {
			const baseUrl = `http://localhost:${this.globalConfig.port}`;
			verifyUrl = `${baseUrl}/rest/external-auth/mock-sirius-token-verify`;
			this.logger.info(`URL: ${verifyUrl}`);
		} else {
			// 从请求头中获取浏览器访问的主机名（不含端口）
			const hostname = req.hostname || req.get('host')?.split(':')[0] || 'localhost';
			const backendSystemUrl = `http://${hostname}`;
			verifyUrl = `${backendSystemUrl}/sirius/api/v2/users/meta/desc/token`;
			this.logger.info(` backendSystemUrl: ${backendSystemUrl}, verifyUrl: ${verifyUrl}`);
		}
		try {
			const response = await fetch(verifyUrl, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({ token }),
			});

			if (!response.ok) {
				throw new AuthError(`Backend system verification failed: ${response.statusText}`);
			}
			const responseData = await response.json();
			const userData = responseData.data || responseData;
			return {
				success: true,
				data: userData,
			};
		} catch (error) {
			if (error instanceof AuthError) {
				throw error;
			}
			throw new AuthError(`Failed to verify token with backend system: ${error.message}`);
		}
	}

	/**
	 * 模拟后台系统的 Token 验证接口 - 仅用于开发测试
	 *
	 * 访问路径：POST /rest/external-auth/mock-sirius-token-verify
	 *
	 * 模拟后台系统接口：/gx/sirius/api/v2/users/meta/desc/token
	 * 测试数据：http://localhost:5678/signin?userId=456&userName=789&token=123
	 */
	@Post('/mock-sirius-token-verify', { skipAuth: true })
	async mockSiriusTokenVerify(req: AuthlessRequest, _res: Response) {
		const payload = req.body as { token?: string };
		const { token } = payload;

		// 模拟验证逻辑：只有 token=123 才返回成功
		if (token === '123') {
			// 直接返回用户数据（verify-backend-token 会包装成 { success: true, data: 用户数据 }）
			return {
				id: '456',
				user_name: '789',
				real_name: '测试用户789',
				email: '789@test.com',
				department: '测试部门',
				phone: '13800138000',
			};
		} else {
			// 模拟 401 未授权错误
			_res.status(401);
			return {
				message: 'Invalid token',
			};
		}
	}

	/**
	 * 设置用户权限接口 - 更新用户的全局角色和项目角色
	 *
	 * 支持的操作：
	 * 1. 修改用户的全局角色
	 * 2. 修改用户在指定项目中的角色
	 *
	 * 限制：
	 * - 不能修改个人项目(personal)中的 project:owner 角色
	 * - 全局角色必须是有效的全局角色之一
	 * - 项目角色必须是有效的项目角色之一（不能设置为 project:owner）
	 */
	@Post('/set-permissions', { skipAuth: true })
	async setPermissions(req: AuthlessRequest, _res: Response) {
		// 1. 获取请求参数
		const payload = req.body as {
			userId?: string;
			authSecret?: string;
			globalRole?: string;
			projectPermissions?: Array<{ projectId: string; role: string }>;
		};
		const { userId, authSecret, globalRole, projectPermissions } = payload;

		// 2. 验证认证密钥
		const expectedSecret = this.globalConfig.externalAuth.secret;
		if (authSecret !== expectedSecret) {
			throw new AuthError('Invalid auth secret');
		}

		// 3. 检查 userId 是否存在
		if (!userId) {
			throw new BadRequestError('userId is required');
		}

		// 4. 格式化邮箱地址
		const emailAddress = userId?.includes('@') ? userId : `${userId}@n8n.local`;

		// 5. 查找用户
		const user = await this.userRepository.findOne({
			where: { email: emailAddress },
			relations: ['role'],
		});

		if (!user) {
			throw new NotFoundError('User not found');
		}

		// 6. 验证并更新全局角色
		if (globalRole) {
			// 验证全局角色是否有效
			const validGlobalRoles = ['global:owner', 'global:admin', 'global:member'];
			if (!validGlobalRoles.includes(globalRole)) {
				throw new BadRequestError(
					`Invalid global role: ${globalRole}. Must be one of: ${validGlobalRoles.join(', ')}`,
				);
			}

			// 检查角色是否存在于数据库
			const role = await this.roleRepository.findOne({
				where: { slug: globalRole },
			});

			if (!role) {
				throw new BadRequestError(`Role not found: ${globalRole}`);
			}

			// 更新用户的全局角色
			await this.userRepository.update({ id: user.id }, { role: { slug: globalRole } });
		}

		// 7. 验证并更新项目角色
		if (projectPermissions && Array.isArray(projectPermissions)) {
			// 验证有效的项目角色（排除 project:owner，它只能用于个人项目）
			const validProjectRoles = ['project:admin', 'project:editor', 'project:viewer'];

			for (const permission of projectPermissions) {
				const { projectId, role } = permission;

				if (!projectId || !role) {
					throw new BadRequestError('Each project permission must have projectId and role');
				}

				// 验证角色是否有效
				if (!validProjectRoles.includes(role)) {
					throw new BadRequestError(
						`Invalid project role: ${role}. Must be one of: ${validProjectRoles.join(', ')}`,
					);
				}

				// 检查项目是否存在
				const project = await this.projectRepository.findOne({
					where: { id: projectId },
				});

				if (!project) {
					throw new BadRequestError(`Project not found: ${projectId}`);
				}

				// 不允许修改个人项目的权限（个人项目的 owner 关系是固定的）
				if (project.type === 'personal') {
					throw new BadRequestError(`Cannot modify permissions for personal project: ${projectId}`);
				}

				// 检查用户是否已经在该项目中
				const existingRelation = await this.projectRelationRepository.findOne({
					where: { projectId, userId: user.id },
				});

				if (!existingRelation) {
					throw new BadRequestError(`User is not a member of project: ${projectId}`);
				}

				// 检查角色是否存在于数据库
				const projectRole = await this.roleRepository.findOne({
					where: { slug: role },
				});

				if (!projectRole) {
					throw new BadRequestError(`Role not found: ${role}`);
				}

				// 更新项目角色
				await this.projectRelationRepository.update(
					{ projectId, userId: user.id },
					{ role: { slug: role } },
				);
			}
		}

		// 8. 返回成功响应
		return {
			success: true,
			message: 'Permissions updated successfully',
		};
	}
}
