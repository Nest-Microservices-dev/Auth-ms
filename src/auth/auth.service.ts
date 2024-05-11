import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { LoginUserDto, RegisterUserDto } from 'src/common';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interfaces';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {

    private readonly logger = new Logger('Auth-Service');

    constructor(
        private readonly jwtService: JwtService
    ) {
        super();
    }

    onModuleInit() {
        this.$connect();
        this.logger.log('MongoDB connected');
    }

    async signJwt(payload: JwtPayload) {
        return this.jwtService.sign(payload);
    }

    async registerUser(registerUserDto: RegisterUserDto) {

        const { email, password, name } = registerUserDto;

        try {

            const user = await this.user.findUnique({
                where: { email }
            });

            if (user) {
                throw new RpcException({
                    status: 400,
                    message: 'User already exists',
                });
            }

            const newUser = await this.user.create({
                data: {
                    name,
                    email,
                    password: bcrypt.hashSync(password, 10)
                }
            });

            const { password: _, ...result } = newUser;

            return {
                user: result,
                token: await this.signJwt(result)
            }

        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message,
            });
        }
    }
    async loginUser(loginUserDto: LoginUserDto) {

        const { email, password } = loginUserDto;

        try {

            const user = await this.user.findUnique({
                where: { email }
            });

            if (!user) {
                throw new RpcException({
                    status: 400,
                    message: 'Invalid credentials',
                });
            }

            const isPasswordValid = bcrypt.compareSync(password, user.password);
            if (!isPasswordValid) {
                throw new RpcException({
                    status: 400,
                    message: 'Invalid password',
                });
            }

            const { password: _, ...result } = user;

            return {
                user: result,
                token: await this.signJwt(result)
            }

        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message,
            });
        }
    }

    async verifyToken(token: string) {
        try {
            const { sub, exp, iat, ...user } = this.jwtService.verify(token, {
                secret: envs.jwtSecret,
            });
            return {
                user,
                token: await this.signJwt(user),
            };
        } catch (error) {
            throw new RpcException({
                status: 401,
                message: 'Invalid token',
            });
        }
    }
}
