import { Injectable } from '@nestjs/common';
import { DbService } from '../../db/db.service';

interface BlacklistedToken {
    token: string;
    expirationTime: number;
    userId?: string;
    type?: 'access' | 'refresh';
    createdAt: Date;
}

@Injectable()
export class TokenBlacklistService {
    private readonly BLACKLIST_PREFIX = 'blacklist:';
    private readonly CLEANUP_INTERVAL = 3600000; // 1 hour

    constructor(private readonly dbService: DbService) {
        // Ejecutar limpieza periódica de tokens expirados
        setInterval(() => {
            this.cleanExpiredTokens().catch(console.error);
        }, this.CLEANUP_INTERVAL);
    }

    async addToBlacklist(token: string, expirationTime: number, userId?: string, type?: 'access' | 'refresh'): Promise<void> {
        const blacklistedToken: BlacklistedToken = {
            token,
            expirationTime,
            userId,
            type,
            createdAt: new Date(),
        };

        const key = `${this.BLACKLIST_PREFIX}${token}`;
        await this.dbService.put(key, blacklistedToken);
    }

    async isBlacklisted(token: string): Promise<boolean> {
        const key = `${this.BLACKLIST_PREFIX}${token}`;
        const blacklistedToken = await this.dbService.get(key);

        if (!blacklistedToken) {
            return false;
        }

        // Verificar si el token ha expirado
        if (Date.now() > blacklistedToken.expirationTime) {
            // Eliminar token expirado
            await this.dbService.del(key);
            return false;
        }

        return true;
    }

    async removeFromBlacklist(token: string): Promise<void> {
        const key = `${this.BLACKLIST_PREFIX}${token}`;
        await this.dbService.del(key);
    }

    async getBlacklistedTokensByUser(userId: string): Promise<BlacklistedToken[]> {
        const allTokens = await this.dbService.getByPrefix(this.BLACKLIST_PREFIX);

        return allTokens
            .map(item => item.value)
            .filter(token => token.userId === userId && Date.now() <= token.expirationTime);
    }

    async revokeAllUserTokens(userId: string): Promise<number> {
        const allTokens = await this.dbService.getByPrefix(this.BLACKLIST_PREFIX);
        let revokedCount = 0;

        for (const { key, value } of allTokens) {
            if (value.userId === userId) {
                await this.dbService.del(key);
                revokedCount++;
            }
        }

        return revokedCount;
    }

    async cleanExpiredTokens(): Promise<number> {
        const allTokens = await this.dbService.getByPrefix(this.BLACKLIST_PREFIX);
        const now = Date.now();
        let cleanedCount = 0;

        for (const { key, value } of allTokens) {
            if (now > value.expirationTime) {
                await this.dbService.del(key);
                cleanedCount++;
            }
        }

        return cleanedCount;
    }

    async getBlacklistStats(): Promise<{
        total: number;
        expired: number;
        active: number;
        byType: { access: number; refresh: number; unknown: number };
    }> {
        const allTokens = await this.dbService.getByPrefix(this.BLACKLIST_PREFIX);
        const now = Date.now();

        let expired = 0;
        let active = 0;
        let accessTokens = 0;
        let refreshTokens = 0;
        let unknownTokens = 0;

        for (const { value } of allTokens) {
            if (now > value.expirationTime) {
                expired++;
            } else {
                active++;
            }

            switch (value.type) {
                case 'access':
                    accessTokens++;
                    break;
                case 'refresh':
                    refreshTokens++;
                    break;
                default:
                    unknownTokens++;
            }
        }

        return {
            total: allTokens.length,
            expired,
            active,
            byType: {
                access: accessTokens,
                refresh: refreshTokens,
                unknown: unknownTokens,
            },
        };
    }

    async getTokenInfo(token: string): Promise<BlacklistedToken | null> {
        const key = `${this.BLACKLIST_PREFIX}${token}`;
        return await this.dbService.get(key);
    }

    async clearAllBlacklisted(): Promise<number> {
        const allTokens = await this.dbService.getByPrefix(this.BLACKLIST_PREFIX);

        for (const { key } of allTokens) {
            await this.dbService.del(key);
        }

        return allTokens.length;
    }
}