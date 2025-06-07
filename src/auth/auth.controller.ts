import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
  Req,
  Get,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiBody,
  ApiUnauthorizedResponse,
  ApiBadRequestResponse,
  ApiConflictResponse,
  ApiNoContentResponse,
} from '@nestjs/swagger';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { AuthenticatedRequest } from './interfaces/request.interface';
import {
  AuthResponseDto,
  TokenResponseDto,
  ValidationResponseDto,
  ErrorResponseDto
} from './dto/auth-response.dto';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'User login',
    description: 'Authenticate user with email and password to receive access and refresh tokens',
  })
  @ApiResponse({
    status: 200,
    description: 'Login successful',
    type: AuthResponseDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid credentials',
    type: ErrorResponseDto,
  })
  @ApiBadRequestResponse({
    description: 'Validation error',
    type: ErrorResponseDto,
  })
  async login(@Body() loginDto: LoginDto) {
    return await this.authService.login(loginDto);
  }

  @Post('register')
  @ApiOperation({
    summary: 'User registration',
    description: 'Register a new user account and receive access and refresh tokens',
  })
  @ApiResponse({
    status: 201,
    description: 'User registered successfully',
    type: AuthResponseDto,
  })
  @ApiConflictResponse({
    description: 'User already exists',
    type: ErrorResponseDto,
  })
  @ApiBadRequestResponse({
    description: 'Validation error',
    type: ErrorResponseDto,
  })
  async register(@Body() registerDto: RegisterDto) {
    return await this.authService.register(registerDto);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Refresh access token',
    description: 'Generate new access and refresh tokens using a valid refresh token',
  })
  @ApiResponse({
    status: 200,
    description: 'Token refreshed successfully',
    type: TokenResponseDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid or expired refresh token',
    type: ErrorResponseDto,
  })
  @ApiBadRequestResponse({
    description: 'Validation error',
    type: ErrorResponseDto,
  })
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    return await this.authService.refreshToken(refreshTokenDto.refreshToken);
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'User logout',
    description: 'Invalidate access and refresh tokens (add them to blacklist)',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        refreshToken: {
          type: 'string',
          description: 'Refresh token to invalidate',
          example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        },
      },
      required: ['refreshToken'],
    },
  })
  @ApiNoContentResponse({
    description: 'Logout successful',
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid or missing token',
    type: ErrorResponseDto,
  })
  async logout(@Req() req: Request & { body: { refreshToken: string } }) {
    const accessToken = req.headers.authorization?.replace('Bearer ', '');
    const refreshToken = req.body.refreshToken;

    if (!accessToken || !refreshToken) {
      throw new Error('Access token and refresh token are required');
    }

    await this.authService.logout(accessToken, refreshToken);
  }

  @Post('forgot-password')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Request password reset',
    description: 'Send password reset instructions to user email (if email exists)',
  })
  @ApiNoContentResponse({
    description: 'Password reset instructions sent (if email exists)',
  })
  @ApiBadRequestResponse({
    description: 'Validation error',
    type: ErrorResponseDto,
  })
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    await this.authService.forgotPassword(forgotPasswordDto);
  }

  @Post('reset-password')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Reset password',
    description: 'Reset user password using a valid reset token',
  })
  @ApiNoContentResponse({
    description: 'Password reset successful',
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid or expired reset token',
    type: ErrorResponseDto,
  })
  @ApiBadRequestResponse({
    description: 'Validation error',
    type: ErrorResponseDto,
  })
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    await this.authService.resetPassword(resetPasswordDto);
  }

  @Get('validate')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: 'Validate access token',
    description: 'Validate the provided access token and return user information',
  })
  @ApiResponse({
    status: 200,
    description: 'Token is valid',
    type: ValidationResponseDto,
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid or expired token',
    type: ErrorResponseDto,
  })
  async validateToken(@Req() req: AuthenticatedRequest) {
    return {
      valid: true,
      user: req.user,
    };
  }
}