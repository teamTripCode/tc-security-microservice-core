import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService as NestJwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from '../interfaces/jwt-payload.interface';

@Injectable()
export class JwtTokenService {
    constructor(
        private readonly jwtService: NestJwtService,
        private readonly configService: ConfigService,
    ) { }

    async generateTokens(payload: JwtPayload): Promise<{
        accessToken: string;
        refreshToken: string;
        expiresIn: number;
    }> {
        const accessTokenPayload = { ...payload };
        const refreshTokenPayload = {
            sub: payload.sub,
            email: payload.email,
            type: 'refresh'
        };

        const accessToken = await this.jwtService.signAsync(accessTokenPayload, {
            secret: this.configService.get('JWT_ACCESS_SECRET'),
            expiresIn: this.configService.get('JWT_ACCESS_EXPIRES_IN', '15m'),
        });

        const refreshToken = await this.jwtService.signAsync(refreshTokenPayload, {
            secret: this.configService.get('JWT_REFRESH_SECRET'),
            expiresIn: this.configService.get('JWT_REFRESH_EXPIRES_IN', '7d'),
        });

        return {
            accessToken,
            refreshToken,
            expiresIn: 15 * 60, // 15 minutes in seconds
        };
    }

    async verifyAccessToken(token: string): Promise<JwtPayload> {
        try {
            return await this.jwtService.verifyAsync(token, {
                secret: this.configService.get('JWT_ACCESS_SECRET'),
            });
        } catch (error) {
            throw new UnauthorizedException('Invalid access token');
        }
    }

    async verifyRefreshToken(token: string): Promise<any> {
        try {
            return await this.jwtService.verifyAsync(token, {
                secret: this.configService.get('JWT_REFRESH_SECRET'),
            });
        } catch (error) {
            throw new UnauthorizedException('Invalid refresh token');
        }
    }
}