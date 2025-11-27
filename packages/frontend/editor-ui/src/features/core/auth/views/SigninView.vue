<script setup lang="ts">
import { computed, reactive, ref, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import AuthView from './AuthView.vue';
import MfaView from './MfaView.vue';

import { useToast } from '@/app/composables/useToast';
import { useI18n } from '@n8n/i18n';
import { useTelemetry } from '@/app/composables/useTelemetry';

import { useUsersStore } from '@/features/settings/users/users.store';
import { useSettingsStore } from '@/app/stores/settings.store';
import { useSSOStore } from '@/features/settings/sso/sso.store';

import type { IFormBoxConfig } from '@/Interface';
import { MFA_AUTHENTICATION_REQUIRED_ERROR_CODE, VIEWS, MFA_FORM } from '@/app/constants';
import type { LoginRequestDto } from '@n8n/api-types';

export type EmailOrLdapLoginIdAndPassword = Pick<
	LoginRequestDto,
	'emailOrLdapLoginId' | 'password'
>;

export type MfaCodeOrMfaRecoveryCode = Pick<LoginRequestDto, 'mfaCode' | 'mfaRecoveryCode'>;

const usersStore = useUsersStore();
const settingsStore = useSettingsStore();
const ssoStore = useSSOStore();

const route = useRoute();
const router = useRouter();

const toast = useToast();
const locale = useI18n();
const telemetry = useTelemetry();

const loading = ref(false);
const showMfaView = ref(false);
const emailOrLdapLoginId = ref('');
const password = ref('');
const reportError = ref(false);

// 自动登录相关状态
const autoLoginMode = ref(false);
const autoLoginMessage = ref('正在自动登录...');

// 访问控制状态
const accessDenied = ref(false);
const accessDeniedMessage = ref('请从后台管理系统跳转登录');

const ldapLoginLabel = computed(() => ssoStore.ldapLoginLabel);
const isLdapLoginEnabled = computed(() => ssoStore.isLdapLoginEnabled);
const emailLabel = computed(() => {
	let label = locale.baseText('auth.email');
	if (isLdapLoginEnabled.value && ldapLoginLabel.value) {
		label = ldapLoginLabel.value;
	}
	return label;
});

const formConfig: IFormBoxConfig = reactive({
	title: locale.baseText('auth.signin'),
	buttonText: locale.baseText('auth.signin'),
	redirectText: locale.baseText('forgotPassword'),
	redirectLink: '/forgot-password',
	inputs: [
		{
			name: 'emailOrLdapLoginId',
			properties: {
				label: emailLabel.value,
				type: 'email',
				required: true,
				...(!isLdapLoginEnabled.value && { validationRules: [{ name: 'VALID_EMAIL' }] }),
				showRequiredAsterisk: false,
				validateOnBlur: false,
				autocomplete: 'email',
				capitalize: true,
				focusInitially: true,
			},
		},
		{
			name: 'password',
			properties: {
				label: locale.baseText('auth.password'),
				type: 'password',
				required: true,
				showRequiredAsterisk: false,
				validateOnBlur: false,
				autocomplete: 'current-password',
				capitalize: true,
			},
		},
	],
});

const onMFASubmitted = async (form: MfaCodeOrMfaRecoveryCode) => {
	await login({
		emailOrLdapLoginId: emailOrLdapLoginId.value,
		password: password.value,
		mfaCode: form.mfaCode,
		mfaRecoveryCode: form.mfaRecoveryCode,
	});
};

const onEmailPasswordSubmitted = async (form: EmailOrLdapLoginIdAndPassword) => {
	await login(form);
};

const isRedirectSafe = () => {
	const redirect = getRedirectQueryParameter();

	// Allow local redirects
	if (redirect.startsWith('/')) {
		return true;
	}

	try {
		// Only allow origin domain redirects
		const url = new URL(redirect);
		return url.origin === window.location.origin;
	} catch {
		return false;
	}
};

const getRedirectQueryParameter = () => {
	let redirect = '';
	if (typeof route.query?.redirect === 'string') {
		redirect = decodeURIComponent(route.query?.redirect);
	}
	return redirect;
};

const login = async (form: LoginRequestDto) => {
	try {
		loading.value = true;
		await usersStore.loginWithCreds({
			emailOrLdapLoginId: form.emailOrLdapLoginId,
			password: form.password,
			mfaCode: form.mfaCode,
			mfaRecoveryCode: form.mfaRecoveryCode,
		});
		loading.value = false;
		await settingsStore.getSettings();

		toast.clearAllStickyNotifications();

		if (settingsStore.isMFAEnforced && !usersStore.currentUser?.mfaAuthenticated) {
			await router.push({ name: VIEWS.PERSONAL_SETTINGS });
			return;
		}

		telemetry.track('User attempted to login', {
			result: showMfaView.value ? 'mfa_success' : 'success',
		});

		if (isRedirectSafe()) {
			const redirect = getRedirectQueryParameter();
			if (redirect.startsWith('http')) {
				window.location.href = redirect;
				return;
			}

			void router.push(redirect);
			return;
		}

		await router.push({ name: VIEWS.HOMEPAGE });
	} catch (error) {
		if (error.errorCode === MFA_AUTHENTICATION_REQUIRED_ERROR_CODE) {
			showMfaView.value = true;
			cacheCredentials(form);
			return;
		}

		telemetry.track('User attempted to login', {
			result: showMfaView.value ? 'mfa_token_rejected' : 'credentials_error',
		});

		if (!showMfaView.value) {
			toast.showError(error, locale.baseText('auth.signin.error'));
			loading.value = false;
			return;
		}

		reportError.value = true;
	}
};

const onBackClick = (fromForm: string) => {
	reportError.value = false;
	if (fromForm === MFA_FORM.MFA_TOKEN) {
		showMfaView.value = false;
		loading.value = false;
	}
};
const onFormChanged = (toForm: string) => {
	if (toForm === MFA_FORM.MFA_RECOVERY_CODE) {
		reportError.value = false;
	}
};
const cacheCredentials = (form: EmailOrLdapLoginIdAndPassword) => {
	emailOrLdapLoginId.value = form.emailOrLdapLoginId;
	password.value = form.password;
};

// 自动登录功能
const performAutoLogin = async (userId: string, userName: string, token: string) => {
	try {
		autoLoginMode.value = true;
		loading.value = true;
		autoLoginMessage.value = '正在验证用户信息...';

		const baseUrl = window.location.origin;
		const authSecret = import.meta.env.VITE_N8N_EXTERNAL_AUTH_SECRET || 'n8n-secret-key-2025';

		// 1. 使用 token 调用 n8n 后端代理接口验证用户信息（避免跨域问题）
		const verifyResponse = await fetch(`${baseUrl}/rest/external-auth/verify-backend-token`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({ token }),
		});

		if (!verifyResponse.ok) {
			throw new Error('后台系统验证失败：无效的 token');
		}
		const verifyResponse_json = await verifyResponse.json();

		// 处理可能的嵌套 data 结构
		let verifyData = verifyResponse_json.data;
		if (verifyData && verifyData.data) {
			verifyData = verifyData.data;
		}
		console.log('verifyData', verifyData);
		// 2. 验证返回的用户信息是否与 URL 参数一致
		if (!verifyData || !verifyData.id || !verifyData.user_name) {
			throw new Error('后台系统返回的用户信息不完整');
		}
		if (verifyData.id !== userId) {
			throw new Error('用户 ID 验证失败：URL 参数与后台系统不一致');
		}
		if (userName && verifyData.user_name !== userName) {
			throw new Error('用户名验证失败：URL 参数与后台系统不一致');
		}

		// 3. 验证通过后，初始化 n8n 用户
		autoLoginMessage.value = '正在初始化用户...';
		const createResponse = await fetch(`${baseUrl}/rest/external-auth/create-user`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				userId: userId,
				firstName: userName,
				lastName: '',
				authSecret: authSecret,
			}),
		});

		if (!createResponse.ok) {
			throw new Error('用户初始化失败');
		}

		// 4. 调用 n8n 登录接口
		autoLoginMessage.value = '正在登录...';
		const loginResponse = await fetch(`${baseUrl}/rest/external-auth/login`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			credentials: 'include',
			body: JSON.stringify({
				userIdentifier: userId,
				authSecret: authSecret,
			}),
		});

		if (!loginResponse.ok) {
			const error = await loginResponse.json();
			throw new Error(error.message || '登录失败');
		}

		// 5. 先保存 token 到 sessionStorage（在 loginWithCookie 之前，确保 loginHook 能获取到正确的 token）
		if (token) {
			sessionStorage.setItem('backend_token', token);
		}

		// 6. 加载用户信息到 store（会触发 loginHook，启动 token 轮询）
		autoLoginMessage.value = '正在加载用户信息...';
		try {
			await usersStore.loginWithCookie();
		} catch (error) {
			throw new Error('登录失败：无法加载用户信息');
		}

		// 7. 登录成功，跳转到工作流页面
		autoLoginMessage.value = '登录成功，正在跳转...';
		await settingsStore.getSettings();

		setTimeout(async () => {
			await router.push('/home/workflows');
		}, 500);
	} catch (error) {
		autoLoginMode.value = false;
		loading.value = false;
		accessDenied.value = true;
		accessDeniedMessage.value = `登录失败: ${error instanceof Error ? error.message : String(error)}`;
	}
};

// 在组件挂载时检查是否有 userId 和 token 参数
onMounted(() => {
	// 0. 清除旧的 backend_token（避免干扰新的登录流程）
	const hasAutoLoginParams = route.query.userId && route.query.token;
	if (hasAutoLoginParams) {
		sessionStorage.removeItem('backend_token');
	}

	// 1. 检查是否是因为 token 失效而被登出
	const tokenExpired = sessionStorage.getItem('token_expired');
	if (tokenExpired === 'true') {
		sessionStorage.removeItem('token_expired');
		// 显示访问受限页面
		accessDenied.value = true;
		accessDeniedMessage.value = '会话已过期，请重新登录';
		autoLoginMode.value = false;
		loading.value = false;
		return;
	}

	// 2. 检查是否携带了自动登录参数
	const userId = route.query.userId as string;
	const userName = route.query.userName as string;
	const token = route.query.token as string;

	// 必须同时有 userId 和 token 才执行自动登录
	if (
		userId &&
		typeof userId === 'string' &&
		userId.trim() &&
		token &&
		typeof token === 'string' &&
		token.trim()
	) {
		void performAutoLogin(userId.trim(), userName?.trim() || '', token.trim());
	} else {
		// 缺少必需参数，显示默认登录表单
		accessDenied.value = true;
		autoLoginMode.value = false;
		loading.value = false;
	}
});
</script>

<template>
	<div>
		<!-- 访问被拒绝页面 -->
		<div v-if="accessDenied" :class="$style.accessDeniedContainer">
			<h1 :class="$style.accessDeniedTitle">访问受限</h1>
			<p :class="$style.accessDeniedMessage">{{ accessDeniedMessage }}</p>
			<div :class="$style.decorationLine"></div>
		</div>

		<!-- 自动登录 Loading 页面 -->
		<div v-else-if="autoLoginMode" :class="$style.autoLoginContainer">
			<div :class="$style.loaderContent">
				<div :class="$style.modernSpinner">
					<div :class="$style.spinnerInner"></div>
					<div :class="$style.spinnerOuter"></div>
				</div>
				<h2 :class="$style.loadingTitle">{{ autoLoginMessage }}</h2>
				<p :class="$style.loadingSubtitle">
					<span :class="$style.dot">.</span>
					<span :class="$style.dot">.</span>
					<span :class="$style.dot">.</span>
				</p>
			</div>
		</div>

		<!-- 禁用原有的登录表单-->
		<AuthView
			v-else-if="!showMfaView"
			:form="formConfig"
			:form-loading="loading"
			:with-sso="true"
			data-test-id="signin-form"
			@submit="onEmailPasswordSubmitted"
		/>
		<MfaView
			v-if="showMfaView"
			:report-error="reportError"
			@submit="onMFASubmitted"
			@on-back-click="onBackClick"
			@on-form-changed="onFormChanged"
		/>
	</div>
</template>

<style lang="scss" module>
.accessDeniedContainer {
	position: fixed;
	top: 0;
	left: 0;
	width: 100%;
	height: 100vh;
	display: flex;
	flex-direction: column;
	align-items: center;
	justify-content: center;
	z-index: 9999;
}

.accessDeniedTitle {
	font-size: 28px;
	font-weight: 700;
	margin: 0 0 16px;
}

.accessDeniedMessage {
	font-size: 16px;
	color: #333333;
	margin-bottom: 24px;
}

/* 自动登录页面 - 科技感风格 */
.autoLoginContainer {
	position: fixed;
	top: 0;
	left: 0;
	width: 100%;
	height: 100vh;
	display: flex;
	align-items: center;
	justify-content: center;
	background: #ffffff;
	z-index: 9999;
}

.loaderContent {
	text-align: center;
	position: relative;
	z-index: 2;
}

.modernSpinner {
	position: relative;
	width: 80px;
	height: 80px;
	margin: 0 auto 30px;
}

.spinnerOuter {
	position: absolute;
	top: 0;
	left: 0;
	width: 100%;
	height: 100%;
	border: 3px solid transparent;
	border-top-color: #ff6b6b;
	border-right-color: #ff6b6b;
	border-radius: 50%;
	animation: spin 1.2s cubic-bezier(0.68, -0.55, 0.265, 1.55) infinite;
}

.spinnerInner {
	position: absolute;
	top: 15px;
	left: 15px;
	width: 50px;
	height: 50px;
	border: 3px solid transparent;
	border-bottom-color: #4ecdc4;
	border-left-color: #4ecdc4;
	border-radius: 50%;
	animation: spinReverse 1.5s linear infinite;
}

.loadingTitle {
	font-size: 24px;
	font-weight: 600;
	color: #2d3436;
	margin-bottom: 12px;
	letter-spacing: 0.5px;
}

.loadingSubtitle {
	font-size: 14px;
	color: #636e72;
	display: flex;
	justify-content: center;
	gap: 4px;
}

.dot {
	animation: bounce 1.4s infinite ease-in-out both;
}

.dot:nth-child(1) {
	animation-delay: -0.32s;
}
.dot:nth-child(2) {
	animation-delay: -0.16s;
}

@keyframes spin {
	0% {
		transform: rotate(0deg);
	}
	100% {
		transform: rotate(360deg);
	}
}

@keyframes spinReverse {
	0% {
		transform: rotate(0deg);
	}
	100% {
		transform: rotate(-360deg);
	}
}

@keyframes pulse {
	0% {
		transform: scale(1);
		opacity: 1;
	}
	50% {
		transform: scale(1.1);
		opacity: 0.8;
	}
	100% {
		transform: scale(1);
		opacity: 1;
	}
}

@keyframes slideUp {
	from {
		transform: translateY(20px);
		opacity: 0;
	}
	to {
		transform: translateY(0);
		opacity: 1;
	}
}

@keyframes bounce {
	0%,
	80%,
	100% {
		transform: scale(0);
	}
	40% {
		transform: scale(1);
	}
}
</style>
