import { Component, OnInit } from '@angular/core';
import { first } from 'rxjs/operators';

import { AccountService, AlertService } from '@app/_services';
import { Account } from '@app/_models';

@Component({ templateUrl: 'list.component.html' })
export class ListComponent implements OnInit {
    accounts: any[];

    constructor(private accountService: AccountService,
        private alertService: AlertService) {}

    ngOnInit() {
        this.accountService.getAll()
            .pipe(first())
            .subscribe(accounts => this.accounts = accounts);
    }

    deleteAccount(id: string) {
        const account = this.accounts.find(x => x.id === id);
        account.isDeleting = true;
        this.accountService.delete(id)
            .pipe(first())
            .subscribe(() => {
                this.accounts = this.accounts.filter(x => x.id !== id) 
            });
    }

    verifyAccount(id: string) {
        const account = this.accounts.find(x => x.id === id);
        account.isVerify = true;
        this.accountService.verifyEmail(account.verificationToken)
            .pipe(first())
            .subscribe(() => {
                this.alertService.success(`Verificacion exitosa, ${ account.userName } puede loguear`);
                this.accountService.getAll()
                    .pipe(first())
                    .subscribe(accounts => this.accounts = accounts);
            });
    }
}