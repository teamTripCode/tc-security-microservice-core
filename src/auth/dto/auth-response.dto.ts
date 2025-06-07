import { ApiProperty } from '@nestjs/swagger';

export class UserResponseDto {
    @ApiProperty({
        description: 'User unique identifier',
        example: 'abc123def456',
    })
    id: string;

    @ApiProperty({
        description: 'User email address',
        example: 'user@example.com',
    })
    email: string;

    @ApiProperty({
        description: 'User first name',
        example: 'John',
    })
    firstName: string;

    @ApiProperty({
        description: 'User last name',
        example: 'Doe',
    })
    lastName: string;

    @ApiProperty({
        description: 'User roles',
        example: ['user', 'admin'],
        type: [String],
    })
    roles: string[];
}

export class AuthResponseDto {
    @ApiProperty({
        description: 'JWT access token',
        example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    })
    accessToken: string;

    @ApiProperty({
        description: 'JWT refresh token',
        example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    })
    refreshToken: string;

    @ApiProperty({
        description: 'Token expiration time in seconds',
        example: 900,
    })
    expiresIn: number;

    @ApiProperty({
        description: 'User information',
        type: UserResponseDto,
    })
    user: UserResponseDto;
}

export class TokenResponseDto {
    @ApiProperty({
        description: 'JWT access token',
        example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    })
    accessToken: string;

    @ApiProperty({
        description: 'JWT refresh token',
        example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    })
    refreshToken: string;

    @ApiProperty({
        description: 'Token expiration time in seconds',
        example: 900,
    })
    expiresIn: number;
}

export class ValidationResponseDto {
    @ApiProperty({
        description: 'Token validation status',
        example: true,
    })
    valid: boolean;

    @ApiProperty({
        description: 'User payload from token',
        example: {
            sub: 'abc123def456',
            email: 'user@example.com',
            roles: ['user'],
            permissions: ['read:profile', 'update:profile'],
        },
    })
    user: any;
}

export class ErrorResponseDto {
    @ApiProperty({
        description: 'HTTP status code',
        example: 401,
    })
    statusCode: number;

    @ApiProperty({
        description: 'Error message',
        example: 'Invalid credentials',
    })
    message: string;

    @ApiProperty({
        description: 'Error type',
        example: 'Unauthorized',
    })
    error: string;
}