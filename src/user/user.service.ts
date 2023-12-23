import { BadRequestException, Injectable } from '@nestjs/common';
import { hash } from 'argon2';
import { PrismaService } from 'src/prisma.service';
import { UserDto } from './dto/user.dto';

@Injectable()
export class UserService {
  constructor(private prismaService: PrismaService) {}

  async createUser(dto: UserDto) {
    if (await this.findUserByEmail(dto.email))
      throw new BadRequestException('This email is taken!');

    const hashedPassword = await hash(dto.password);

    const newUser = await this.prismaService.user.create({
      data: {
        ...dto,
        password: hashedPassword,
        avatarPath: '',
        surname: '',
      },
    });

    const { password, createdAt, updatedAt, ...result } = newUser;

    return result;
  }

  async findUserByEmail(email: string) {
    return this.prismaService.user.findFirst({ where: { email } });
  }

  async getUserById(id: number) {
    return this.prismaService.user.findUnique({ where: { id } });
  }
}
