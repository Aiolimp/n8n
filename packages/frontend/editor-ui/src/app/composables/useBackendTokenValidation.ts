import { ref } from 'vue';
import { useUsersStore } from '@/features/settings/users/users.store';

const POLL_INTERVAL = 30000; // 30秒

// 全局共享状态
let globalPollTimer: NodeJS.Timeout | null = null;
let globalBackendToken: string | null = null; // 全局后台系统 token
let isPollingActive = false; // 是否已经开启了轮训

/**
 * 用于定时验证后台系统的 token 是否仍然有效
 * 如果 token 失效，自动登出 n8n 并跳转回后台系统
 */
export function useBackendTokenValidation() {
	const usersStore = useUsersStore();
	const isValidating = ref(false);

	/**
	 * 验证后台系统的 token 是否有效
	 */
	const validateToken = async (): Promise<boolean> => {
		console.log('[Token Validation] validateToken 被调用');
		console.log(
			'[Token Validation] globalBackendToken:',
			globalBackendToken?.substring(0, 10) + '...',
		);
		console.log('[Token Validation] isValidating:', isValidating.value);

		if (!globalBackendToken || isValidating.value) {
			console.log('[Token Validation] 跳过验证 - 无 token 或正在验证中');
			return true;
		}

		try {
			isValidating.value = true;

			// 调用 n8n 后端代理接口验证 token（避免跨域问题）
			const baseUrl = window.location.origin;
			const apiUrl = `${baseUrl}/rest/external-auth/verify-backend-token`;
			console.log('[Token Validation] 调用验证接口:', apiUrl);

			const response = await fetch(apiUrl, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({ token: globalBackendToken }),
			});

			console.log('[Token Validation] 响应状态:', response.status);

			if (!response.ok) {
				console.log('[Token Validation] Token 验证失败，触发 handleTokenExpired');
				await handleTokenExpired();
				return false;
			}

			// 验证响应数据
			const responseData = await response.json();
			console.log('[Token Validation] 响应数据:', responseData);
			return true;
		} catch (error) {
			// 网络错误时不强制登出，避免误判
			console.error('[Token Validation] Token 验证异常:', error);
			return true;
		} finally {
			isValidating.value = false;
		}
	};

	/**
	 * 处理 token 失效的情况
	 */
	const handleTokenExpired = async () => {
		try {
			stopPolling();
			sessionStorage.removeItem('backend_token');

			// 如果当前已经在登录页，不需要处理（避免循环）
			if (window.location.pathname === '/signin') {
				return;
			}

			sessionStorage.setItem('token_expired', 'true');
			await usersStore.logout();

			setTimeout(() => {
				window.location.href = '/signin';
			}, 100);
		} catch (error) {
			// 如果已经在登录页，不需要跳转
			if (window.location.pathname !== '/signin') {
				window.location.href = '/signin';
			}
		}
	};

	/**
	 * 启动轮询
	 */
	const startPolling = (token: string) => {
		console.log('[Token Validation] startPolling 被调用, token:', token?.substring(0, 10) + '...');
		console.log(
			'[Token Validation] 当前状态 - isPollingActive:',
			isPollingActive,
			'globalBackendToken:',
			globalBackendToken?.substring(0, 10) + '...',
		);

		// 如果已经开启了轮训，并且 token 相同，则直接返回
		if (isPollingActive && globalBackendToken === token) {
			console.log('[Token Validation] 轮询已启动且 token 相同，跳过');
			return;
		}

		// 如果已经开启了轮训，并且 token 不同，则停止轮训
		if (isPollingActive && globalBackendToken !== token) {
			console.log('[Token Validation] 轮询已启动但 token 不同，停止旧轮询');
			stopPolling();
		}

		globalBackendToken = token;
		isPollingActive = true;

		console.log('[Token Validation] 立即执行第一次验证');
		void validateToken();

		console.log(
			'[Token Validation] 启动定时器，间隔:',
			POLL_INTERVAL,
			'ms (',
			POLL_INTERVAL / 1000,
			'秒)',
		);
		globalPollTimer = setInterval(() => {
			console.log('[Token Validation] 定时器触发 - 执行 token 验证');
			void validateToken();
		}, POLL_INTERVAL);
	};

	/**
	 * 停止轮询
	 */
	const stopPolling = () => {
		if (globalPollTimer) {
			clearInterval(globalPollTimer);
			globalPollTimer = null;
			globalBackendToken = null;
			isPollingActive = false;
		}
	};

	return {
		startPolling,
		stopPolling,
		validateToken,
	};
}
