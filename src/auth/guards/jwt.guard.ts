import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import type { Request } from 'express';

@Injectable()
export class JwtGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();

    const token = this.getTokenFromHeaders(req);
    if (!token) throw new ForbiddenException('No token');

    try {
      const payload = await this.jwtService.verifyAsync(token, {
        secret: this.configService.get('ACCESS_KEY'),
      });

      req['user'] = payload;
    } catch (error) {
      throw new UnauthorizedException('Token is incorrect');
    }

    return true;
  }

  private getTokenFromHeaders(req: Request) {
    const [type, token] = req.headers.authorization.split(' ');
    return type === 'Bearer' ? token : undefined;
  }
}
