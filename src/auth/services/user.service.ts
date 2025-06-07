import { Injectable, NotFoundException } from '@nestjs/common';
import { User } from '../interfaces/user.interface';
import { RegisterDto } from '../dto/register.dto';

@Injectable()
export class UserService {
    // En un caso real, esto sería una conexión a base de datos o otro microservicio
    private users: User[] = [];

    async findByEmail(email: string): Promise<User | null> {
        const user = this.users.find(u => u.email === email && u.isActive);
        return user || null;
    }

    async findById(id: string): Promise<User | null> {
        const user = this.users.find(u => u.id === id && u.isActive);
        return user || null;
    }

    async create(registerDto: RegisterDto): Promise<User> {
        const existingUser = await this.findByEmail(registerDto.email);
        if (existingUser) {
            throw new Error('User already exists');
        }

        const newUser: User = {
            id: this.generateId(),
            email: registerDto.email,
            password: registerDto.password, // En producción, hashear la contraseña
            firstName: registerDto.firstName,
            lastName: registerDto.lastName,
            phone: registerDto.phone,
            roles: ['user'], // rol por defecto
            permissions: ['read:profile', 'update:profile'],
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date(),
        };

        this.users.push(newUser);
        return newUser;
    }

    async updatePassword(userId: string, newPassword: string): Promise<void> {
        const user = await this.findById(userId);
        if (!user) {
            throw new NotFoundException('User not found');
        }

        user.password = newPassword; // En producción, hashear la contraseña
        user.updatedAt = new Date();
    }

    private generateId(): string {
        return Math.random().toString(36).substr(2, 9);
    }
}