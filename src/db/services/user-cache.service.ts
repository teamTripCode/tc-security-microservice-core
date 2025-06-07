import { Injectable } from '@nestjs/common';
import { LevelDbService } from './leveldb.service';

export interface CachedUserSession {
    userId: string;
    email: string;
    roles: string[];
    permissions: string[];
    lastActivity: Date;
    loginCount: number;
    failedLoginAttempts: number;
    lockedUntil?: Date;
}

@Injectable()
export class UserCacheService {
    private readonly USER_SESSION_PREFIX = 'user_session:';
    private readonly LOGIN_ATTEMPTS_PREFIX = 'login_attempts:';
    private readonly CLEANUP_INTERVAL = 7200000; // 2 hours

    constructor(private readonly levelDbService: LevelDbService) {
        // Ejecutar limpieza periódica
        setInterval(() => {
            this.cleanExpiredSessions().catch(console.error);
        }, this.CLEANUP_INTERVAL);
    }

    async storeUserSession(session: CachedUserSession): Promise<void> {
        const key = `${this.USER_SESSION_PREFIX}${session.userId}`;
        await this.levelDbService.put(key, session);
    }

    async getUserSession(userId: string): Promise<CachedUserSession | null> {
        const key = `${this.USER_SESSION_PREFIX}${userId}`;
        return await this.levelDbService.get(key);
    }

    async updateLastActivity(userId: string): Promise<void> {
        const session = await this.getUserSession(userId);
        if (session) {
            session.lastActivity = new Date();
            await this.storeUserSession(session);
        }
    }

    async incrementLoginCount(userId: string): Promise<void> {
        const session = await this.getUserSession(userId);
        if (session) {
            session.loginCount++;
            session.lastActivity = new Date();
            await this.storeUserSession(session);
        }
    }

    async removeUserSession(userId: string): Promise<void> {
        const key = `${this.USER_SESSION_PREFIX}${userId}`;
        await this.levelDbService.del(key);
    }

    // Gestión de intentos de login fallidos
    async recordFailedLogin(email: string): Promise<number> {
        const key = `${this.LOGIN_ATTEMPTS_PREFIX}${email}`;
        const attempts = await this.levelDbService.get(key) || {
            email,
            attempts: 0,
            lastAttempt: new Date(),
            lockedUntil: null,
        };

        attempts.attempts++;
        attempts.lastAttempt = new Date();

        // Bloquear después de 5 intentos fallidos
        if (attempts.attempts >= 5) {
            attempts.lockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutos
        }

        await this.levelDbService.put(key, attempts);
        return attempts.attempts;
    }

    async clearFailedLogins(email: string): Promise<void> {
        const key = `${this.LOGIN_ATTEMPTS_PREFIX}${email}`;
        await this.levelDbService.del(key);
    }

    async isAccountLocked(email: string): Promise<boolean> {
        const key = `${this.LOGIN_ATTEMPTS_PREFIX}${email}`;
        const attempts = await this.levelDbService.get(key);

        if (!attempts || !attempts.lockedUntil) {
            return false;
        }

        const now = new Date();
        if (now > new Date(attempts.lockedUntil)) {
            // El bloqueo ha expirado, limpiar
            await this.clearFailedLogins(email);
            return false;
        }

        return true;
    }

    async getFailedLoginAttempts(email: string): Promise<number> {
        const key = `${this.LOGIN_ATTEMPTS_PREFIX}${email}`;
        const attempts = await this.levelDbService.get(key);
        return attempts ? attempts.attempts : 0;
    }

    async cleanExpiredSessions(): Promise<void> {
        const allSessions = await this.levelDbService.getByPrefix(this.USER_SESSION_PREFIX);
        const inactivityLimit = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 horas

        for (const { key, value } of allSessions) {
            if (new Date(value.lastActivity) < inactivityLimit) {
                await this.levelDbService.del(key);
            }
        }
    }

    async getActiveUserCount(): Promise<number> {
        const allSessions = await this.levelDbService.getByPrefix(this.USER_SESSION_PREFIX);
        const activeLimit = new Date(Date.now() - 60 * 60 * 1000); // 1 hora

        return allSessions.filter(({ value }) =>
            new Date(value.lastActivity) >= activeLimit
        ).length;
    }

    async getUserStatistics(userId: string): Promise<{
        loginCount: number;
        lastActivity: Date;
        failedAttempts: number;
        isLocked: boolean;
    } | null> {
        const session = await this.getUserSession(userId);
        if (!session) {
            return null;
        }

        return {
            loginCount: session.loginCount,
            lastActivity: session.lastActivity,
            failedAttempts: session.failedLoginAttempts,
            isLocked: false, // Se puede implementar lógica adicional
        };
    }
}