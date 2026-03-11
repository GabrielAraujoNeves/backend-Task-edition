import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { Public } from '../common/decorators/public.decorator';
import { Throttle } from '@nestjs/throttler';
import {
    ApiTags,
    ApiOperation,
    ApiResponse,
    ApiBearerAuth,
} from '@nestjs/swagger';
import { LoginDto } from './dto/login.dto';
import { AuthResponseDto } from './dto/user-response.dto';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/Register.dto';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import type { JwtPayload } from '../common/decorators/current-user.decorator';



@Controller('auth')
export class AuthController {

    constructor(
        private readonly authService: AuthService
    ) { }

    @Public()
    @Post('login')
    @HttpCode(HttpStatus.OK)
    @Throttle({ default: { limit: 5, ttl: 60000 } })
    @ApiOperation({ summary: 'Login com email e senha' })
    @ApiResponse({ status: 200, description: 'Login realizado com sucesso' })
    @ApiResponse({ status: 401, description: 'Credenciais invalidas' })
    @ApiResponse({
        status: 429,
        description:
            'Muitas tentativas de login. Tente novamente em algum minutos',
    })

    async login(@Body() dto: LoginDto): Promise<AuthResponseDto> {
        return this.authService.login(dto);
    }

    @Public()
    @Post('register')
    @Throttle({ default: { limit: 3, ttl: 60000 } })
    @ApiOperation({ summary: 'Registrar novo usuário' })
    @ApiResponse({ status: 201, description: 'Usuário criado com sucesso' })
    @ApiResponse({ status: 409, description: 'Email já em uso' })
    @ApiResponse({
        status: 429,
        description: 'Muitas tentativas de registro. Tente novamente em alguns minutos.',
    })
    async register(@Body() dto: RegisterDto): Promise<AuthResponseDto> {
        return this.authService.register(dto);
    }

    @Post('refresh')
    @HttpCode(HttpStatus.OK)
    @ApiBearerAuth('JWT')
    @ApiOperation({
        summary: 'Refresh token (valida Bearer e retorna user + token)',
    })
    @ApiResponse({ status: 200, description: 'Token válido' })
    @ApiResponse({ status: 401, description: 'Token inválido ou expirado' })
    async refresh(@CurrentUser() payload: JwtPayload): Promise<AuthResponseDto> {
        return this.authService.refresh(payload);
    }

}
