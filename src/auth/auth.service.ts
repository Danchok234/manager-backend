import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { verify } from 'argon2';
import { UserDto } from 'src/user/dto/user.dto';
import { UserService } from 'src/user/user.service';
import { LoginUserDto } from './dto/loginUser.dto';

type TSub = {
  name: string;
};

interface IPayload {
  email: string;
  sub: TSub;
}

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async regsiter(user: UserDto) {
    const newUser = await this.userService.createUser(user);

    const payload: IPayload = {
      email: newUser.email,
      sub: {
        name: newUser.name,
      },
    };

    const backendTokends = await this.signNewTokens(payload);

    return {
      user: newUser,
      backendTokends,
    };
  }

  async login(dto: LoginUserDto) {
    const currentUser = await this.validateUser(dto);
    const payload = {
      email: currentUser.email,
      sub: {
        name: currentUser.name,
      },
    };
    const backendTokens = await this.signNewTokens(payload);

    const { createdAt, updatedAt, password, ...user } = currentUser;

    return {
      user,
      backendTokens,
    };
  }

  async validateUser(dto: LoginUserDto) {
    const currentUser = await this.userService.findUserByEmail(dto.email);

    if (!currentUser) throw new BadRequestException('User isn`t exist!');

    if (!(await verify(currentUser.password, dto.password)))
      throw new ForbiddenException('Password is incorrect!');

    return currentUser;
  }

  async signNewTokens(payload: IPayload) {
    const accessToken = await this.jwtService.signAsync(payload, {
      expiresIn: '1d',
      secret: this.configService.get('ACCESS_KEY'),
    });
    const refreshToken = await this.jwtService.signAsync(payload, {
      expiresIn: '7d',
      secret: this.configService.get('REFRESH_KEY'),
    });

    return {
      accessToken,
      refreshToken,
    };
  }

  async refreshToken(user: any) {
    const payload: IPayload = {
      email: user.email,
      sub: {
        name: user.name,
      },
    };
    return await this.signNewTokens(payload);
  }
}
