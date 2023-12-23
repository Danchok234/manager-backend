import { IsString, MinLength } from 'class-validator';

export class UserDto {
  @IsString()
  email: string;

  @IsString()
  name: string;

  @MinLength(8)
  @IsString()
  password: string;
}
