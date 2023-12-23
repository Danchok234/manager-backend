import { Body, Controller, Post, Request, UseGuards } from '@nestjs/common';
import { UserDto } from 'src/user/dto/user.dto';
import { AuthService } from './auth.service';
import { LoginUserDto } from './dto/loginUser.dto';
import { RefreshJwtGuard } from './guards/refresh.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() user: UserDto) {
    return await this.authService.regsiter(user);
  }

  @Post('login')
  async login(@Body() user: LoginUserDto) {
    return await this.authService.login(user);
  }

  @UseGuards(RefreshJwtGuard)
  @Post('refresh')
  async refresh(@Request() req: any) {
    return await this.authService.refreshToken(req.user);
  }
}
