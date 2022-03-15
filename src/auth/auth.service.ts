import { ForbiddenException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import { Tokens } from './types';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwtService: JwtService) {}

    async signupLocal(dto: AuthDto): Promise<Tokens> {
        const hash = await this.hashData(dto.password);

        const newUser = await this.prisma.user.create({
            data: {
                email: dto.email,
                hash,
            },
        });

        const tokens = await this.getTokens(newUser.id, newUser.email);

        // save refresh token in db
        await this.updateRtHash(newUser.id, tokens.refresh_token);

        return tokens;
    }

    async signinLocal(dto: AuthDto): Promise<Tokens> {
        // find the user with email
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            },
        });

        if (!user) {
            throw new ForbiddenException('credentials incorrect');
        }

        // match user password
        const isPasswordMatch = await bcrypt.compare(dto.password, user.hash);

        if (!isPasswordMatch) {
            throw new ForbiddenException('credentials incorrect');
        }

        const tokens = await this.getTokens(user.id, user.email);

        // save refresh token in db
        await this.updateRtHash(user.id, tokens.refresh_token);

        return tokens;
    }

    async logout(userId: number) {
        await this.prisma.user.updateMany({
            where: {
                id: userId,
                hashedRt: {
                    not: null,
                },
            },
            data: {
                hashedRt: null,
            },
        });
    }

    async refreshTokens(userId: number, rt: string): Promise<Tokens> {
        const user = await this.prisma.user.findUnique({
            where: {
                id: userId,
            },
        });

        if (!user || !user.hashedRt) {
            throw new ForbiddenException('Access denied');
        }

        // match user refresh token with saved refresh token
        const iseRtMatch = await bcrypt.compare(rt, user.hashedRt);

        if (!iseRtMatch) {
            throw new ForbiddenException('Access denied');
        }

        const tokens = await this.getTokens(user.id, user.email);

        // save refresh token in db
        await this.updateRtHash(user.id, tokens.refresh_token);

        return tokens;
    }

    async updateRtHash(userId: number, rt: string) {
        const hash = await this.hashData(rt);

        await this.prisma.user.update({
            where: {
                id: userId,
            },
            data: {
                hashedRt: hash,
            },
        });
    }

    hashData(data: string) {
        return bcrypt.hash(data, 10);
    }

    async getTokens(userId: number, email: string) {
        const [at, rt] = await Promise.all([
            // access token
            this.jwtService.signAsync(
                {
                    sub: userId,
                    email,
                },
                {
                    secret: 'at_secret',
                    expiresIn: 60 * 15, // 15 min
                }
            ),

            // refresh token
            this.jwtService.signAsync(
                {
                    sub: userId,
                    email,
                },
                {
                    secret: 'rt_secret',
                    expiresIn: 60 * 60 * 24 * 7, // 1 week
                }
            ),
        ]);

        return {
            access_token: at,
            refresh_token: rt,
        };
    }
}
