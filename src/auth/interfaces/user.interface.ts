export interface User {
    id: string;
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    phone?: string;
    roles: string[];
    permissions: string[];
    isActive: boolean;
    createdAt: Date;
    updatedAt: Date;
}