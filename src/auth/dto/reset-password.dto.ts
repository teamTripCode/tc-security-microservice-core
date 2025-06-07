import { ApiProperty } from '@nestjs/swagger';
import { IsString, MinLength } from 'class-validator';

export class ResetPasswordDto {
  @ApiProperty({
    description: 'Password reset token received via email',
    example: 'abc123def456ghi789',
  })
  @IsString()
  token: string;

  @ApiProperty({
    description: 'New password for the user account',
    example: 'myNewSecurePassword123',
    minLength: 6,
  })
  @IsString()
  @MinLength(6)
  newPassword: string;
}