import { ConflictException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

export interface CreateUserData {
    email: string;
    name: string;
    passwordHash?: string | null;
    avatar?: string;
    provider?: string;
    providerId?: string;
}

export interface UserForAuth {
    id: string;
    name: string;
    email: string;
    avatar: string | null;
}

export interface UserWithPassword extends UserForAuth {
    passwordHash: string | null;
}

@Injectable()
export class UsersService {

    constructor(private prisma: PrismaService) { }

    async findByEmail(email: string): Promise<UserWithPassword | null> {
        return this.prisma.user.findUnique({
            where: { email: email.toLowerCase() },
            select: {
                id: true,
                email: true,
                name: true,
                avatar: true,
                passwordHash: true,
            },
        });
    }

    async findByProvider(
        provider: string,
        providerId: string,
    ): Promise<UserForAuth | null> {
        return this.prisma.user.findFirst({
            where: { provider, providerId },
            select: {
                id: true,
                email: true,
                name: true,
                avatar: true,
            },
        });
    }

    async create(data: CreateUserData): Promise<UserForAuth> {
        const email = data.email.toLowerCase();
        const existing = await this.findByEmail(email);
        if (existing) {
            throw new ConflictException('Este email já está em uso');
        }
        const user = await this.prisma.user.create({
            data: {
                email,
                name: data.name.trim(),
                ...(data.passwordHash != null && { passwordHash: data.passwordHash }),
                ...(data.avatar != null && { avatar: data.avatar }),
                ...(data.provider != null && { provider: data.provider }),
                ...(data.providerId != null && { providerId: data.providerId }),
            },
            select: {
                id: true,
                email: true,
                name: true,
                avatar: true,
            },
        });
        return user;
    }


    async findById(id: string): Promise<UserForAuth | null> {
        return this.prisma.user.findUnique({
            where: { id },
            select: {
                id: true,
                email: true,
                name: true,
                avatar: true,
            },
        })
    }
}
