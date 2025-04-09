import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ApiOperationDecorator, Public } from '@nnpp/decorators';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { RequestLoginDto } from './dto/login.dto';
import { UserResponseWrapperDto } from './dto/user.response.dto';

@ApiTags('Auth')
@ApiBearerAuth()
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiOperationDecorator({
    operationId: 'loginUser',
    summary: 'Login',
    description: 'Login to get access token',
  })
  @ApiResponse({
    status: 200,
    description: 'User logged in successfully',
    type: UserResponseWrapperDto,
  })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  @Public()
  @Post('login')
  async login(@Body() data: RequestLoginDto): Promise<UserResponseWrapperDto> {
    const user = await this.authService.login(data.user);
    const token = await this.authService.generateToken(user);
    return new UserResponseWrapperDto(user, token);
  }
}
