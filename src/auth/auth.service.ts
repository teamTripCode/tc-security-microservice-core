import {
  Injectable,
  UnauthorizedException,
  ConflictException,
} from '@nestjs/common';
import { UserService } from './services/user.service';
import { PasswordService } from './services/password.service';
import { JwtTokenService } from './services/jwt.service';
import { TokenBlacklistService } from './services/token-blacklist.service';
import { DbService } from '../db/db.service';
import { AuthResponse } from './interfaces/auth-response.interface';
import { LoginDto } from './dto/login.dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { RegisterDto } from './dto/register.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';

interface ResetTokenData {
  userId: string;
  expiresAt: Date;
  createdAt: Date;
  used: boolean;
}

@Injectable()
export class AuthService {
  private readonly RESET_TOKEN_PREFIX = 'reset_token:';

  constructor(
    private readonly userService: UserService,
    private readonly passwordService: PasswordService,
    private readonly jwtTokenService: JwtTokenService,
    private readonly tokenBlacklistService: TokenBlacklistService,
    private readonly dbService: DbService,
  ) { }

  async login(loginDto: LoginDto): Promise<AuthResponse> {
    // Verificar si la cuenta está bloqueada por intentos fallidos
    const isLocked = await this.isAccountLocked(loginDto.email);
    if (isLocked) {
      throw new UnauthorizedException('Account temporarily locked due to multiple failed attempts');
    }

    const user = await this.userService.findByEmail(loginDto.email);
    if (!user) {
      await this.recordFailedLogin(loginDto.email);
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await this.passwordService.comparePassword(
      loginDto.password,
      user.password,
    );

    if (!isPasswordValid) {
      await this.recordFailedLogin(loginDto.email);
      throw new UnauthorizedException('Invalid credentials');
    }

    // Limpiar intentos fallidos en login exitoso
    await this.clearFailedLoginAttempts(loginDto.email);

    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      roles: user.roles,
      permissions: user.permissions,
    };

    const tokens = await this.jwtTokenService.generateTokens(payload);

    // Guardar información de sesión
    await this.storeUserSession(user.id, {
      userId: user.id,
      email: user.email,
      roles: user.roles,
      permissions: user.permissions,
      lastActivity: new Date(),
      loginCount: await this.incrementLoginCount(user.id),
    });

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

      // Guardar información de sesión inicial
      await this.storeUserSession(user.id, {
        userId: user.id,
        email: user.email,
        roles: user.roles,
        permissions: user.permissions,
        lastActivity: new Date(),
        loginCount: 1,
      });

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

    if (await this.tokenBlacklistService.isBlacklisted(refreshToken)) {
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

    // Actualizar última actividad
    await this.updateLastActivity(user.id);

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

    // Remover sesión del usuario
    await this.removeUserSession(accessPayload.sub);
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<void> {
    const user = await this.userService.findByEmail(forgotPasswordDto.email);
    if (!user) {
      // Por seguridad, no revelamos si el email existe o no
      return;
    }

    // Revocar todos los tokens de reset existentes para este usuario
    await this.revokeAllUserResetTokens(user.id);

    const resetToken = this.passwordService.generateResetToken();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutos

    const resetTokenData: ResetTokenData = {
      userId: user.id,
      expiresAt,
      createdAt: new Date(),
      used: false,
    };

    await this.dbService.put(`${this.RESET_TOKEN_PREFIX}${resetToken}`, resetTokenData);

    // Aquí enviarías el email con el token de reset
    console.log(`Reset token for ${user.email}: ${resetToken}`);
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto): Promise<void> {
    const resetData = await this.dbService.get(`${this.RESET_TOKEN_PREFIX}${resetPasswordDto.token}`);

    if (!resetData || resetData.used || new Date(resetData.expiresAt) < new Date()) {
      throw new UnauthorizedException('Invalid or expired reset token');
    }

    const hashedPassword = await this.passwordService.hashPassword(resetPasswordDto.newPassword);
    await this.userService.updatePassword(resetData.userId, hashedPassword);

    // Marcar el token como usado
    resetData.used = true;
    await this.dbService.put(`${this.RESET_TOKEN_PREFIX}${resetPasswordDto.token}`, resetData);

    // Revocar todos los tokens JWT del usuario por seguridad
    await this.revokeAllUserTokens(resetData.userId);
  }

  async validateToken(token: string): Promise<JwtPayload> {
    if (await this.tokenBlacklistService.isBlacklisted(token)) {
      throw new UnauthorizedException('Token has been revoked');
    }

    const payload = await this.jwtTokenService.verifyAccessToken(token);

    // Actualizar última actividad
    await this.updateLastActivity(payload.sub);

    return payload;
  }

  // Métodos privados para gestión de usuarios y sesiones
  private async storeUserSession(userId: string, sessionData: any): Promise<void> {
    await this.dbService.put(`user_session:${userId}`, sessionData);
  }

  private async getUserSession(userId: string): Promise<any> {
    return await this.dbService.get(`user_session:${userId}`);
  }

  private async updateLastActivity(userId: string): Promise<void> {
    const session = await this.getUserSession(userId);
    if (session) {
      session.lastActivity = new Date();
      await this.storeUserSession(userId, session);
    }
  }

  private async removeUserSession(userId: string): Promise<void> {
    await this.dbService.del(`user_session:${userId}`);
  }

  private async incrementLoginCount(userId: string): Promise<number> {
    const session = await this.getUserSession(userId);
    const currentCount = session?.loginCount || 0;
    return currentCount + 1;
  }

  // Gestión de intentos de login fallidos
  private async recordFailedLogin(email: string): Promise<void> {
    const key = `failed_login:${email}`;
    const attempts = await this.dbService.get(key) || {
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

    await this.dbService.put(key, attempts);
  }

  private async clearFailedLoginAttempts(email: string): Promise<void> {
    await this.dbService.del(`failed_login:${email}`);
  }

  private async isAccountLocked(email: string): Promise<boolean> {
    const attempts = await this.dbService.get(`failed_login:${email}`);

    if (!attempts || !attempts.lockedUntil) {
      return false;
    }

    const now = new Date();
    if (now > new Date(attempts.lockedUntil)) {
      // El bloqueo ha expirado, limpiar
      await this.clearFailedLoginAttempts(email);
      return false;
    }

    return true;
  }

  private async revokeAllUserResetTokens(userId: string): Promise<void> {
    const resetTokens = await this.dbService.getByPrefix(this.RESET_TOKEN_PREFIX);

    for (const { key, value } of resetTokens) {
      if (value.userId === userId) {
        await this.dbService.del(key);
      }
    }
  }

  private async revokeAllUserTokens(userId: string): Promise<void> {
    // Esto requeriría almacenar una relación entre tokens y usuarios
    // Por ahora, solo removemos la sesión
    await this.removeUserSession(userId);
  }

  // Métodos públicos para administración
  async getUserStatistics(userId: string): Promise<any> {
    const session = await this.getUserSession(userId);
    const failedAttempts = await this.dbService.get(`failed_login:${userId}`);

    return {
      session,
      failedLoginAttempts: failedAttempts?.attempts || 0,
      isLocked: failedAttempts?.lockedUntil ? new Date() < new Date(failedAttempts.lockedUntil) : false,
    };
  }

  async cleanExpiredResetTokens(): Promise<number> {
    const resetTokens = await this.dbService.getByPrefix(this.RESET_TOKEN_PREFIX);
    const now = new Date();
    let cleanedCount = 0;

    for (const { key, value } of resetTokens) {
      if (now > new Date(value.expiresAt)) {
        await this.dbService.del(key);
        cleanedCount++;
      }
    }

    return cleanedCount;
  }

  async getActiveUserCount(): Promise<number> {
    const sessions = await this.dbService.getByPrefix('user_session:');
    const activeLimit = new Date(Date.now() - 30 * 60 * 1000); // 30 minutos

    return sessions.filter(({ value }) =>
      new Date(value.lastActivity) >= activeLimit
    ).length;
  }
}