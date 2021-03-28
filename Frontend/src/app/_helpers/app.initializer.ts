import { AccountService } from '@app/_services';

export function appInitializer(accountService: AccountService) {
    return () => new Promise(resolve => {
        // Intentamos actualizar el token al inicio de la app para autenticar auto
        accountService.refreshToken()
            .subscribe()
            .add(resolve);
    });
}