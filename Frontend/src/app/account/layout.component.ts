import { Component } from '@angular/core';
import { Router } from '@angular/router';

import { AccountService } from '@app/_services';

@Component({ templateUrl: 'layout.component.html' })
export class LayoutComponent {
    constructor(
        private router: Router,
        private accountService: AccountService
    ) {
        //Vamos al home si ya esta logueado
        if (this.accountService.accountValue) {
            this.router.navigate(['/']);
        }
    }
}