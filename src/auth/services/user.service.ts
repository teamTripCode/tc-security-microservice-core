import { Injectable, NotFoundException } from '@nestjs/common';
import { DbService } from '../../db/db.service';
import { User } from '../interfaces/user.interface';
import { RegisterDto } from '../dto/register.dto';

@Injectable()
export class UserService {
    private readonly USER_PREFIX = 'user:';
    private readonly USER_EMAIL_INDEX = 'user_email:';

    constructor(private readonly dbService: DbService) { }

    async findByEmail(email: string): Promise<User | null> {
        // Buscar el ID del usuario por email
        const userId = await this.dbService.get(`${this.USER_EMAIL_INDEX}${email.toLowerCase()}`);

        if (!userId) {
            return null;
        }

        // Obtener el usuario completo
        const user = await this.dbService.get(`${this.USER_PREFIX}${userId}`);

        if (!user || !user.isActive) {
            return null;
        }

        return user;
    }

    async findById(id: string): Promise<User | null> {
        const user = await this.dbService.get(`${this.USER_PREFIX}${id}`);

        if (!user || !user.isActive) {
            return null;
        }

        return user;
    }

    async create(registerDto: RegisterDto): Promise<User> {
        const existingUser = await this.findByEmail(registerDto.email);
        if (existingUser) {
            throw new Error('User already exists');
        }

        const userId = this.generateId();
        const newUser: User = {
            id: userId,
            email: registerDto.email.toLowerCase(),
            password: registerDto.password,
            firstName: registerDto.firstName,
            lastName: registerDto.lastName,
            phone: registerDto.phone,
            roles: ['user'], // rol por defecto
            permissions: ['read:profile', 'update:profile'],
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date(),
        };

        // Guardar usuario
        await this.dbService.put(`${this.USER_PREFIX}${userId}`, newUser);

        // Crear índice de email para búsqueda rápida
        await this.dbService.put(`${this.USER_EMAIL_INDEX}${newUser.email}`, userId);

        return newUser;
    }

    async updatePassword(userId: string, newPassword: string): Promise<void> {
        const user = await this.findById(userId);
        if (!user) {
            throw new NotFoundException('User not found');
        }

        user.password = newPassword;
        user.updatedAt = new Date();

        await this.dbService.put(`${this.USER_PREFIX}${userId}`, user);
    }

    async updateUser(userId: string, updateData: Partial<User>): Promise<User> {
        const user = await this.findById(userId);
        if (!user) {
            throw new NotFoundException('User not found');
        }

        // Si se actualiza el email, actualizar el índice
        if (updateData.email && updateData.email !== user.email) {
            const existingUserWithEmail = await this.findByEmail(updateData.email);
            if (existingUserWithEmail && existingUserWithEmail.id !== userId) {
                throw new Error('Email already in use');
            }

            // Eliminar el índice anterior
            await this.dbService.del(`${this.USER_EMAIL_INDEX}${user.email}`);

            // Crear nuevo índice
            await this.dbService.put(`${this.USER_EMAIL_INDEX}${updateData.email.toLowerCase()}`, userId);
        }

        const updatedUser: User = {
            ...user,
            ...updateData,
            id: userId, // Asegurar que el ID no se cambie
            updatedAt: new Date(),
        };

        await this.dbService.put(`${this.USER_PREFIX}${userId}`, updatedUser);

        return updatedUser;
    }

    async deactivateUser(userId: string): Promise<void> {
        const user = await this.findById(userId);
        if (!user) {
            throw new NotFoundException('User not found');
        }

        user.isActive = false;
        user.updatedAt = new Date();

        await this.dbService.put(`${this.USER_PREFIX}${userId}`, user);
    }

    async activateUser(userId: string): Promise<void> {
        const user = await this.dbService.get(`${this.USER_PREFIX}${userId}`);
        if (!user) {
            throw new NotFoundException('User not found');
        }

        user.isActive = true;
        user.updatedAt = new Date();

        await this.dbService.put(`${this.USER_PREFIX}${userId}`, user);
    }

    async deleteUser(userId: string): Promise<void> {
        const user = await this.dbService.get(`${this.USER_PREFIX}${userId}`);
        if (!user) {
            throw new NotFoundException('User not found');
        }

        // Eliminar índice de email
        await this.dbService.del(`${this.USER_EMAIL_INDEX}${user.email}`);

        // Eliminar usuario
        await this.dbService.del(`${this.USER_PREFIX}${userId}`);
    }

    async getAllUsers(options: {
        includeInactive?: boolean;
        limit?: number;
        offset?: number;
    } = {}): Promise<{
        users: User[];
        total: number;
    }> {
        const allUsers = await this.dbService.getByPrefix(this.USER_PREFIX);

        let users = allUsers.map(item => item.value);

        if (!options.includeInactive) {
            users = users.filter(user => user.isActive);
        }

        const total = users.length;

        // Aplicar paginación si se especifica
        if (options.offset !== undefined) {
            users = users.slice(options.offset);
        }

        if (options.limit !== undefined) {
            users = users.slice(0, options.limit);
        }

        return {
            users,
            total,
        };
    }

    async getUsersByRole(role: string): Promise<User[]> {
        const allUsers = await this.dbService.getByPrefix(this.USER_PREFIX);

        return allUsers
            .map(item => item.value)
            .filter(user => user.isActive && user.roles.includes(role));
    }

    async updateUserRoles(userId: string, roles: string[]): Promise<User> {
        const user = await this.findById(userId);
        if (!user) {
            throw new NotFoundException('User not found');
        }

        user.roles = roles;
        user.updatedAt = new Date();

        await this.dbService.put(`${this.USER_PREFIX}${userId}`, user);

        return user;
    }

    async updateUserPermissions(userId: string, permissions: string[]): Promise<User> {
        const user = await this.findById(userId);
        if (!user) {
            throw new NotFoundException('User not found');
        }

        user.permissions = permissions;
        user.updatedAt = new Date();

        await this.dbService.put(`${this.USER_PREFIX}${userId}`, user);

        return user;
    }

    async searchUsers(query: string, options: {
        field?: 'email' | 'firstName' | 'lastName' | 'all';
        limit?: number;
    } = {}): Promise<User[]> {
        const { field = 'all', limit = 50 } = options;
        const allUsers = await this.dbService.getByPrefix(this.USER_PREFIX);
        const searchTerm = query.toLowerCase();

        let filteredUsers = allUsers
            .map(item => item.value)
            .filter(user => user.isActive);

        switch (field) {
            case 'email':
                filteredUsers = filteredUsers.filter(user =>
                    user.email.toLowerCase().includes(searchTerm)
                );
                break;
            case 'firstName':
                filteredUsers = filteredUsers.filter(user =>
                    user.firstName.toLowerCase().includes(searchTerm)
                );
                break;
            case 'lastName':
                filteredUsers = filteredUsers.filter(user =>
                    user.lastName.toLowerCase().includes(searchTerm)
                );
                break;
            default:
                filteredUsers = filteredUsers.filter(user =>
                    user.email.toLowerCase().includes(searchTerm) ||
                    user.firstName.toLowerCase().includes(searchTerm) ||
                    user.lastName.toLowerCase().includes(searchTerm)
                );
        }

        return filteredUsers.slice(0, limit);
    }

    async getUserCount(): Promise<{
        total: number;
        active: number;
        inactive: number;
    }> {
        const allUsers = await this.dbService.getByPrefix(this.USER_PREFIX);
        const users = allUsers.map(item => item.value);

        const active = users.filter(user => user.isActive).length;
        const inactive = users.filter(user => !user.isActive).length;

        return {
            total: users.length,
            active,
            inactive,
        };
    }

    private generateId(): string {
        return Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
    }
}