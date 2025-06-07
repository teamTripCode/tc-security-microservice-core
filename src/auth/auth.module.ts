import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { UserService } from './services/user.service';
import { PasswordService } from './services/password.service';
import { JwtTokenService } from './services/jwt.service';
import { TokenBlacklistService } from './services/token-blacklist.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Module({
  imports: [
    ConfigModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_ACCESS_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('JWT_ACCESS_EXPIRES_IN', '15m'),
        },
      }),
      inject: [ConfigService],
    }),
    AuthModule
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    UserService,
    PasswordService,
    JwtTokenService,
    TokenBlacklistService,
    JwtAuthGuard,
    JwtService
  ],
})
export class AuthModule { }
