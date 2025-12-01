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
		console.log('isValidating:', isValidating.value);
		if (!globalBackendToken || isValidating.value) {
			console.log('跳过验证 - 无 token 或正在验证中');
			return true;
		}

		try {
			isValidating.value = true;
			// 调用 n8n 后端代理接口验证 token（避免跨域问题）
			const baseUrl = window.location.origin;
			const apiUrl = `${baseUrl}/rest/external-auth/verify-backend-token`;
			console.log('调用验证接口:', apiUrl);
			const response = await fetch(apiUrl, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({ token: globalBackendToken }),
			});
			console.log('响应状态:', response);
			if (!response.ok) {
				console.log('Token 验证失败，触发 handleTokenExpired');
				await handleTokenExpired();
				return false;
			}
			// 验证响应数据
			const responseData = await response.json();
			console.log('响应数据:', responseData);
			return true;
		} catch (error) {
			// 网络错误时不强制登出，避免误判
			console.error('Token 验证异常:', error);
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
			localStorage.removeItem('backend_token');
			await usersStore.logout();
			const backendSystemUrl = `${window.location.protocol}//${window.location.hostname}`;
			window.location.href = `${backendSystemUrl}/login`;
		} catch (error) {
			const backendSystemUrl = `${window.location.protocol}//${window.location.hostname}`;
			window.location.href = `${backendSystemUrl}/login`;
		}
	};

	/**
	 * 启动轮询
	 */
	const startPolling = (token: string) => {
		console.log('开启轮训验证');
		// 如果已经开启了轮训，并且 token 相同，则直接返回
		if (isPollingActive && globalBackendToken === token) {
			console.log('轮询已启动且 token 相同，跳过');
			return;
		}

		// 如果已经开启了轮训，并且 token 不同，则停止轮训
		if (isPollingActive && globalBackendToken !== token) {
			console.log('轮询已启动但 token 不同，停止旧轮询');
			stopPolling();
		}

		globalBackendToken = token;
		isPollingActive = true;

		console.log('立即执行第一次验证');
		void validateToken();
		globalPollTimer = setInterval(() => {
			console.log('定时器触发 - 执行 token 验证');
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
