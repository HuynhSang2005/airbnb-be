import { forwardRef, Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { config } from '../../config';

const jwtModule = JwtModule.register({
  global: true,
  secret: config.jwt.secret,
  signOptions: { expiresIn: config.jwt.expiresIn },
});

@Module({
  imports: [jwtModule],
  controllers: [AuthController],
  providers: [AuthService],
  exports: [AuthService],
})
export class AuthModule {}
