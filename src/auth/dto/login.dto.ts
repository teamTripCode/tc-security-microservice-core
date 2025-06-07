
import { ApiProperty } from '@nestjs/swagger';
import {
    IsEmail,
    IsString,
    MinLength
} from 'class-validator';

export class LoginDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
    format: 'email',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'User password',
    example: 'mySecurePassword123',
    minLength: 6,
  })
  @IsString()
  @MinLength(6)
  password: string;
}