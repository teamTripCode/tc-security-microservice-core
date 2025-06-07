import {
  Injectable,
  UnauthorizedException,
  ConflictException,
} from '@nestjs/common';
import { UserService } from './services/user.service';
import { PasswordService } from './services/password.service';
import { JwtTokenService } from './services/jwt.service';
import { TokenBlacklistService } from './services/token-blacklist.service';
import { AuthResponse } from './interfaces/auth-response.interface';
import { LoginDto } from './dto/login.dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { RegisterDto } from './dto/register.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';

@Injectable()
export class AuthService {
  private resetTokens: Map<string, { userId: string; expiresAt: Date }> = new Map();

  constructor(
    private readonly userService: UserService,
    private readonly passwordService: PasswordService,
    private readonly jwtTokenService: JwtTokenService,
    private readonly tokenBlacklistService: TokenBlacklistService,
  ) { }

  async login(loginDto: LoginDto): Promise<AuthResponse> {
    const user = await this.userService.findByEmail(loginDto.email);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await this.passwordService.comparePassword(
      loginDto.password,
      user.password,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      roles: user.roles,
      permissions: user.permissions,
    };

    const tokens = await this.jwtTokenService.generateTokens(payload);

    return {
      ...tokens,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        roles: user.roles,
      },
    };
  }

  async register(registerDto: RegisterDto): Promise<AuthResponse> {
    try {
      const hashedPassword = await this.passwordService.hashPassword(registerDto.password);

      const user = await this.userService.create({
        ...registerDto,
        password: hashedPassword,
      });

      const payload: JwtPayload = {
        sub: user.id,
        email: user.email,
        roles: user.roles,
        permissions: user.permissions,
      };

      const tokens = await this.jwtTokenService.generateTokens(payload);

      return {
        ...tokens,
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          roles: user.roles,
        },
      };
    } catch (error) {
      if (error.message === 'User already exists') {
        throw new ConflictException('User already exists');
      }
      throw error;
    }
  }

  async refreshToken(refreshToken: string): Promise<Omit<AuthResponse, 'user'>> {
    const payload = await this.jwtTokenService.verifyRefreshToken(refreshToken);

    if (this.tokenBlacklistService.isBlacklisted(refreshToken)) {
      throw new UnauthorizedException('Token has been revoked');
    }

    const user = await this.userService.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const newPayload: JwtPayload = {
      sub: user.id,
      email: user.email,
      roles: user.roles,
      permissions: user.permissions,
    };

    // Invalidar el refresh token anterior
    this.tokenBlacklistService.addToBlacklist(refreshToken, payload.exp * 1000);

    const tokens = await this.jwtTokenService.generateTokens(newPayload);

    return tokens;
  }

  async logout(accessToken: string, refreshToken: string): Promise<void> {
    const accessPayload = await this.jwtTokenService.verifyAccessToken(accessToken);
    const refreshPayload = await this.jwtTokenService.verifyRefreshToken(refreshToken);

    // Agregar ambos tokens a la lista negra
    if (typeof accessPayload.exp === 'number') {
      this.tokenBlacklistService.addToBlacklist(accessToken, accessPayload.exp * 1000);
    } else {
      throw new UnauthorizedException('Invalid access token payload');
    }
    if (typeof refreshPayload.exp === 'number') {
      this.tokenBlacklistService.addToBlacklist(refreshToken, refreshPayload.exp * 1000);
    } else {
      throw new UnauthorizedException('Invalid refresh token payload');
    }
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<void> {
    const user = await this.userService.findByEmail(forgotPasswordDto.email);
    if (!user) {
      // Por seguridad, no revelamos si el email existe o no
      return;
    }

    const resetToken = this.passwordService.generateResetToken();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutos

    this.resetTokens.set(resetToken, {
      userId: user.id,
      expiresAt,
    });

    // Aquí enviarías el email con el token de reset
    console.log(`Reset token for ${user.email}: ${resetToken}`);
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto): Promise<void> {
    const resetData = this.resetTokens.get(resetPasswordDto.token);

    if (!resetData || resetData.expiresAt < new Date()) {
      throw new UnauthorizedException('Invalid or expired reset token');
    }

    const hashedPassword = await this.passwordService.hashPassword(resetPasswordDto.newPassword);
    await this.userService.updatePassword(resetData.userId, hashedPassword);

    // Eliminar el token usado
    this.resetTokens.delete(resetPasswordDto.token);
  }

  async validateToken(token: string): Promise<JwtPayload> {
    if (this.tokenBlacklistService.isBlacklisted(token)) {
      throw new UnauthorizedException('Token has been revoked');
    }

    return await this.jwtTokenService.verifyAccessToken(token);
  }
}