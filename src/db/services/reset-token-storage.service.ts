import { Injectable } from '@nestjs/common';
import { DbService } from '../db.service';

export interface ResetToken {
    token: string;
    userId: string;
    expiresAt: Date;
    createdAt: Date;
    used: boolean;
}

@Injectable()
export class ResetTokenStorageService {
    private readonly RESET_TOKEN_PREFIX = 'reset_token:';
    private readonly CLEANUP_INTERVAL = 1800000; // 30 minutes

    constructor(private readonly levelDbService: DbService) {
        // Ejecutar limpieza periódica de tokens expirados
        setInterval(() => {
            this.cleanExpiredTokens().catch(console.error);
        }, this.CLEANUP_INTERVAL);
    }

    async storeResetToken(
        token: string,
        userId: string,
        expiresAt: Date
    ): Promise<void> {
        const resetToken: ResetToken = {
            token,
            userId,
            expiresAt,
            createdAt: new Date(),
            used: false,
        };

        const key = `${this.RESET_TOKEN_PREFIX}${token}`;
        await this.levelDbService.put(key, resetToken);
    }

    async getResetToken(token: string): Promise<ResetToken | null> {
        const key = `${this.RESET_TOKEN_PREFIX}${token}`;
        const resetToken = await this.levelDbService.get(key);

        if (!resetToken) {
            return null;
        }

        // Verificar si el token ha expirado
        if (new Date() > new Date(resetToken.expiresAt)) {
            // Eliminar token expirado
            await this.levelDbService.del(key);
            return null;
        }

        return resetToken;
    }

    async markTokenAsUsed(token: string): Promise<void> {
        const key = `${this.RESET_TOKEN_PREFIX}${token}`;
        const resetToken = await this.levelDbService.get(key);

        if (resetToken) {
            resetToken.used = true;
            await this.levelDbService.put(key, resetToken);
        }
    }

    async deleteResetToken(token: string): Promise<void> {
        const key = `${this.RESET_TOKEN_PREFIX}${token}`;
        await this.levelDbService.del(key);
    }

    async revokeAllUserResetTokens(userId: string): Promise<void> {
        const allTokens = await this.levelDbService.getByPrefix(this.RESET_TOKEN_PREFIX);

        for (const { key, value } of allTokens) {
            if (value.userId === userId) {
                await this.levelDbService.del(key);
            }
        }
    }

    async cleanExpiredTokens(): Promise<number> {
        const allTokens = await this.levelDbService.getByPrefix(this.RESET_TOKEN_PREFIX);
        const now = new Date();
        let cleanedCount = 0;

        for (const { key, value } of allTokens) {
            if (now > new Date(value.expiresAt)) {
                await this.levelDbService.del(key);
                cleanedCount++;
            }
        }

        return cleanedCount;
    }

    async getUserResetTokens(userId: string): Promise<ResetToken[]> {
        const allTokens = await this.levelDbService.getByPrefix(this.RESET_TOKEN_PREFIX);
        const now = new Date();

        return allTokens
            .map(item => item.value)
            .filter(token =>
                token.userId === userId &&
                now <= new Date(token.expiresAt)
            );
    }
}