import { Controller, Get, Post, Query, Req, Res, UseGuards, UnauthorizedException, Logger } from '@nestjs/common';
import { JwtGuard } from './guards/jwt.guard';
import { Response } from 'express';
import { AuthService } from './auth.service';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';
import { UserService } from 'src/user/user.service';
import { ChatGateway } from 'src/socket.io/chat/chat.gateway';

@Controller('auth')
export class AuthController {
    private readonly logger = new Logger(AuthController.name);
    constructor(
        private authService: AuthService,
		private userService: UserService,
        private chatGateway: ChatGateway
    ) {}

    @Get('login')
    async login(@Req() req: any, @Query('code') code: string, @Res() res: Response) {
        if (!code) {
            throw new UnauthorizedException('No code in query string');
        }

        this.logger.log("42api callback code:" + code);

        // get user data from api
        const apiData = await this.authService.getUserFromApi(code);

        const user = await this.userService.createUser({
            // id: apiData.id,
            name: apiData.name,
            email: apiData.email,
        });

        if (user.is2faEnabled) {
            return res.send({
                message: 'you must authenticate 2fa to get jwt token.',
                id: user.id,
                name: user.name,
                email: user.email,
                nickname: user.nickname,
                isNewUser: user.isNewUser,
                is2faEnabled: true,
            });
        }

        const access_token = await this.authService.generateAccessToken({
            id: user.id,
            name: user.name,
            email: user.email
        });
        const refresh_token = await this.authService.generateRefreshToken({
            id: user.id,
            name: user.name,
            email: user.email
        });

        // hashing refresh token
        const hashedRefreshToken = await this.authService.getHashedRefreshToken(refresh_token);
        // store hashed refresh token
		this.userService.updateUserById(user.id, {
			refreshToken : hashedRefreshToken
		});

        res.setHeader('Authorization', 'Bearer '+ [access_token, refresh_token]);
        res.cookie('access_token', access_token, {
            httpOnly: true,
        });
        res.cookie('refresh_token', refresh_token, {
            httpOnly: true,
        });

        return res.send({
            message: 'new jwt generated',
            id: user.id,
            name: user.name,
            email: user.email,
            nickname: user.nickname,
            isNewUser: user.isNewUser,
            is2faEnabled: false,
            access_token: access_token
        });
    }

    @UseGuards(JwtRefreshGuard)
    @Get('refresh')
    async refresh(@Req() req: any, @Res() res: Response) {
        const user = await this.userService.findUserById(req.user.id);

        const access_token = await this.authService.generateAccessToken({
            id: user.id,
            name: user.name,
            email: user.email,
        });
        res.setHeader('Authorization', 'Bearer '+ access_token);
        res.cookie('access_token', access_token, {
            httpOnly: true,
        });
        return res.send({
            message: 'generate new access token',
            access_token: access_token,
            access_token_exp: process.env.JWT_ACCESS_EXPIRATION_TIME,
        });
    }

    @UseGuards(JwtRefreshGuard)
    @Post('logout')
    async logout(@Req() req: any, @Res() res: Response) {
		await this.userService.updateUserById(req.user.id, {
			refreshToken : null,
		})
        res.clearCookie('access_token');
        res.clearCookie('refresh_token');
        this.chatGateway.logout(req.user.id);
        return res.send({
            message: 'logout success'
        });
    }
}
