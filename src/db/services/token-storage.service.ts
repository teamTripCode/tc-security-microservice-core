import { Injectable } from '@nestjs/common';
import { LevelDbService } from './leveldb.service';

export interface BlacklistedToken {
    token: string;
    expirationTime: number;
    userId: string;
    type: 'access' | 'refresh';
    createdAt: Date;
}

@Injectable()
export class TokenStorageService {
    private readonly BLACKLIST_PREFIX = 'blacklist:';
    private readonly CLEANUP_INTERVAL = 3600000; // 1 hour

    constructor(private readonly levelDbService: LevelDbService) {
        // Ejecutar limpieza periódica de tokens expirados
        setInterval(() => {
            this.cleanExpiredTokens().catch(console.error);
        }, this.CLEANUP_INTERVAL);
    }

    async addToBlacklist(
        token: string,
        expirationTime: number,
        userId: string,
        type: 'access' | 'refresh'
    ): Promise<void> {
        const blacklistedToken: BlacklistedToken = {
            token,
            expirationTime,
            userId,
            type,
            createdAt: new Date(),
        };

        const key = `${this.BLACKLIST_PREFIX}${token}`;
        await this.levelDbService.put(key, blacklistedToken);
    }

    async isBlacklisted(token: string): Promise<boolean> {
        const key = `${this.BLACKLIST_PREFIX}${token}`;
        const blacklistedToken = await this.levelDbService.get(key);

        if (!blacklistedToken) {
            return false;
        }

        // Verificar si el token ha expirado
        if (Date.now() > blacklistedToken.expirationTime) {
            // Eliminar token expirado
            await this.levelDbService.del(key);
            return false;
        }

        return true;
    }

    async removeFromBlacklist(token: string): Promise<void> {
        const key = `${this.BLACKLIST_PREFIX}${token}`;
        await this.levelDbService.del(key);
    }

    async getBlacklistedTokensByUser(userId: string): Promise<BlacklistedToken[]> {
        const allTokens = await this.levelDbService.getByPrefix(this.BLACKLIST_PREFIX);

        return allTokens
            .map(item => item.value)
            .filter(token => token.userId === userId && Date.now() <= token.expirationTime);
    }

    async revokeAllUserTokens(userId: string): Promise<void> {
        const userTokens = await this.getBlacklistedTokensByUser(userId);

        for (const tokenData of userTokens) {
            const key = `${this.BLACKLIST_PREFIX}${tokenData.token}`;
            await this.levelDbService.del(key);
        }
    }

    async cleanExpiredTokens(): Promise<number> {
        const allTokens = await this.levelDbService.getByPrefix(this.BLACKLIST_PREFIX);
        const now = Date.now();
        let cleanedCount = 0;

        for (const { key, value } of allTokens) {
            if (now > value.expirationTime) {
                await this.levelDbService.del(key);
                cleanedCount++;
            }
        }

        return cleanedCount;
    }

    async getBlacklistStats(): Promise<{
        total: number;
        expired: number;
        active: number;
        byType: { access: number; refresh: number };
    }> {
        const allTokens = await this.levelDbService.getByPrefix(this.BLACKLIST_PREFIX);
        const now = Date.now();

        let expired = 0;
        let active = 0;
        let accessTokens = 0;
        let refreshTokens = 0;

        for (const { value } of allTokens) {
            if (now > value.expirationTime) {
                expired++;
            } else {
                active++;
            }

            if (value.type === 'access') {
                accessTokens++;
            } else {
                refreshTokens++;
            }
        }

        return {
            total: allTokens.length,
            expired,
            active,
            byType: {
                access: accessTokens,
                refresh: refreshTokens,
            },
        };
    }
}