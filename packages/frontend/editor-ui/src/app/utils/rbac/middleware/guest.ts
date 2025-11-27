import type { RouterMiddleware } from '@/app/types/router';
import type { GuestPermissionOptions } from '@/app/types/rbac';
import { isGuest } from '@/app/utils/rbac/checks';
import { useUsersStore } from '@/features/settings/users/users.store';

export const guestMiddleware: RouterMiddleware<GuestPermissionOptions> = async (
	to,
	_from,
	_next,
) => {
	const valid = isGuest();

	if (!valid) {
		// 已登录用户访问登录页，需要先登出
		const usersStore = useUsersStore();

		try {
			await usersStore.logout();
		} catch (error) {}

		return;
	}
};
