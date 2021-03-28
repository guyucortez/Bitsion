import { Role } from './role';

export class Account {
    id: string;
    title: string;
    firstName: string;
    lastName: string;
    userName: string;
    role: Role;
    jwtToken?: string;
    verificationToken: String;
    isVerified: boolean;
}