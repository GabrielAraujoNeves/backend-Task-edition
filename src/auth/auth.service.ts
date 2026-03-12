import { BadRequestException, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { LoginDto } from './dto/login.dto';
import { AuthResponseDto, UserResponseDto } from './dto/user-response.dto';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { RegisterDto } from './dto/Register.dto';
import { JwtPayload } from '../common/decorators/current-user.decorator';
import { UpdateProfileDto } from './dto/update-profile.dto';
import * as crypto from 'crypto';
import { MailService } from '../service/mail.service';

@Injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name);
    private readonly saltRounds = 10;

    constructor(
        private usersService: UsersService,
        private jwtService: JwtService,
        private configService: ConfigService,
        private mailService: MailService
    ) { }

    async login(dto: LoginDto): Promise<AuthResponseDto> {
        const user = await this.usersService.findByEmail(dto.email);
        if (!user) {
            throw new UnauthorizedException("Email ou senha invalidos")
        }
        if (!user.passwordHash) {
            throw new UnauthorizedException(
                'Esta conta usa login com Google ou GitHub. Use um deles para entrar.',
            );
        }
        const isPasswordValid = await bcrypt.compare(
            dto.password,
            user.passwordHash,
        );
        if (!isPasswordValid) {
            throw new UnauthorizedException('Email ou senbha invalidos')
        }
        return this.buildAuthResponse(user);
    }

    async register(dto: RegisterDto): Promise<AuthResponseDto> {
        const passwordHash = await bcrypt.hash(dto.password, this.saltRounds);
        const user = await this.usersService.create({
            email: dto.email,
            name: dto.name,
            passwordHash,
        });
        return this.buildAuthResponse(user);
    }


    private async buildAuthResponse(user: {
        id: string;
        email: string;
        name: string;
        avatar: string | null;
    }): Promise<AuthResponseDto> {
        const expiresIn = this.configService.get<string>('jwt.expiresIn') ?? '7d';
        const expiresInSeconds =
            expiresIn === '7d' ? 604800 : parseInt(expiresIn, 10) || 604800;
        const token = this.jwtService.sign(
            { sub: user.id, email: user.email },
            {
                secret:
                    this.configService.get<string>('jwt.secret') ?? 'default-secret',
                expiresIn: expiresInSeconds,
            },
        );
        const userResponse: UserResponseDto = {
            id: user.id,
            name: user.name,
            email: user.email,
            avatar: user.avatar ?? undefined,
        };
        return { user: userResponse, token };
    }

    async refresh(payload: JwtPayload): Promise<AuthResponseDto> {
        const user = await this.usersService.findById(payload.sub);
        if (!user) {
            throw new UnauthorizedException('Usuário não encontrado');
        }
        return this.buildAuthResponse(user);
    }

    async getProfile(payload: JwtPayload): Promise<UserResponseDto> {
        const user = await this.usersService.findById(payload.sub);
        if (!user) {
            throw new UnauthorizedException('Usuário não encontrado');
        }
        return {
            id: user.id,
            name: user.name,
            email: user.email,
            avatar: user.avatar ?? undefined,
        };
    }

    async updateProfile(payLoad: JwtPayload, dto: UpdateProfileDto): Promise<UserResponseDto> {
        const userId = payLoad.sub;
        let passwordHash: string | undefined;
        if (dto.password !== undefined && dto.password.trim() !== '') {
            if (!dto.confirmPassword || dto.confirmPassword.trim() === '') {
                throw new BadRequestException('confirme a senha');
            }
            if (dto.password !== dto.confirmPassword) {
                throw new BadRequestException('As senha não coincidem');
            }
            passwordHash = await bcrypt.hash(dto.password, this.saltRounds);
        }
        const user = await this.usersService.updateProfile(userId, {
            ...(dto.name !== undefined && { name: dto.name }),
            ...(dto.email !== undefined && { email: dto.email }),
            ...(passwordHash !== undefined && { passwordHash }),
        });
        return {
            id: user.id,
            name: user.name,
            email: user.email,
            avatar: user.avatar ?? undefined,
        };
    }

    async forgotPassword(email: string): Promise<void> {
        this.logger.log(`Initiating password reset for email: ${email}`);
        const user = await this.usersService.findByEmail(email);

        if (!user) {
            this.logger.log(`User not found for email: ${email}`);
            return;
        }

        const token = crypto.randomBytes(32).toString('hex');
        const expires = new Date();
        expires.setHours(expires.getHours() + 1);
        this.logger.log(`Generated reset token for ${email}, updating database`);
        try {
            await this.usersService.updateResetToken(user.id, token, expires);
            this.logger.log(`Database updated. Sending password reset email`);
            await this.mailService.sendPasswordResetEmail(user.email, token);
            this.logger.log(`Password reset email sent successfully`);
        } catch (error) {
            this.logger.error(`Error during password reset process:`, error);
            throw error;
        }
    }
}
