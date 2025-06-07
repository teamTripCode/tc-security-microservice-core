export interface StorageProvider {
    get(key: string): Promise<any>;
    set(key: string, value: any, ttl?: number): Promise<void>;
    del(key: string): Promise<void>;
    exists(key: string): Promise<boolean>;
    clear(): Promise<void>;
}

export interface TokenStorage {
    addToBlacklist(token: string, expirationTime: number, userId: string, type: 'access' | 'refresh'): Promise<void>;
    isBlacklisted(token: string): Promise<boolean>;
    removeFromBlacklist(token: string): Promise<void>;
    cleanExpiredTokens(): Promise<number>;
}

export interface ResetTokenStorage {
    storeResetToken(token: string, userId: string, expiresAt: Date): Promise<void>;
    getResetToken(token: string): Promise<any>;
    deleteResetToken(token: string): Promise<void>;
    cleanExpiredTokens(): Promise<number>;
}