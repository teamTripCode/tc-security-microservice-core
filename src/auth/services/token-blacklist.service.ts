import { Injectable } from '@nestjs/common';

@Injectable()
export class TokenBlacklistService {
    private blacklistedTokens: Set<string> = new Set();
    private tokenExpirations: Map<string, number> = new Map();

    addToBlacklist(token: string, expirationTime: number): void {
        this.blacklistedTokens.add(token);
        this.tokenExpirations.set(token, expirationTime);

        // Limpiar tokens expirados cada hora
        setTimeout(() => this.cleanExpiredTokens(), 3600000);
    }

    isBlacklisted(token: string): boolean {
        return this.blacklistedTokens.has(token);
    }

    private cleanExpiredTokens(): void {
        const now = Date.now();
        for (const [token, expiration] of this.tokenExpirations.entries()) {
            if (now > expiration) {
                this.blacklistedTokens.delete(token);
                this.tokenExpirations.delete(token);
            }
        }
    }
}