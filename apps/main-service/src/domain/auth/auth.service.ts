import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../user/user.service';
import { LoginDto } from './dto/login.dto';
import { User } from '@prisma/client';
import bcrypt from 'bcryptjs';
import { config } from '../../config';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
  ) {}

  private async comparePassword(
    plainPassword: string,
    hashedPassword: string,
  ): Promise<boolean> {
    try {
      return await bcrypt.compare(plainPassword, hashedPassword);
    } catch (error) {
      return false;
    }
  }

  async login(data: LoginDto): Promise<User> {
    // find user theo email
    const user = await this.userService.findByEmail(data.email);
    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    // compare password
    const isPasswordValid = await this.comparePassword(
      data.password,
      user.password,
    );
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid email or password');
    }

    return user;
  }

  async generateToken(user: User) {
    const payload = {
      sub: user.id,
      email: user.email,
      username: user.username,
      iss: config.jwt.issuer,
    };

    return this.jwtService.signAsync(payload, {
      secret: config.jwt.secret,
      expiresIn: config.jwt.expiresIn,
    });
  }

  async validateToken(token: string): Promise<any> {
    try {
      return await this.jwtService.verifyAsync(token, {
        secret: config.jwt.secret,
      });
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }
}
