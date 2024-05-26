import { Body, Controller, Get, Post, Req, Res, UnauthorizedException, UseGuards } from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthService } from 'src/auth/auth.service';
import { JwtGuard } from 'src/auth/guards/jwt.guard';
import { User } from '@prisma/client';
import { TwoFactorAuthService } from './two-factor-auth.service';
import { UserService } from 'src/user/user.service';
import { TwoFactorAuthCodeDto } from './dto/2fa-code.dto';

@Controller('2fa')
export class TwoFactorAuthController {
    constructor(
        private authService: AuthService,
        private twoFactorAuthService: TwoFactorAuthService,
		private userService : UserService
    ) {}

    @Post('authenticate')
    async authenticate(
        @Res() res: Response,
        @Body() twoFactorAuthCode: TwoFactorAuthCodeDto
    ) {
        const user = await this.userService.findUserById(twoFactorAuthCode.id);
        if (!user) {
            throw new UnauthorizedException('No user in database');
        }

        const isCodeValidated = await this.twoFactorAuthService.isTwoFactorAuthCodeValid(
            twoFactorAuthCode.twoFactorAuthCode, user
        )

        if (!isCodeValidated) {
            throw new UnauthorizedException('Invalid otp code');
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
        res.clearCookie('id');
        res.cookie('access_token', access_token, {
            httpOnly: true,
        });
        res.cookie('refresh_token', refresh_token, {
            httpOnly: true,
        });

        return res.send({
            message: 'new jwt generated',
            access_token: access_token,
        });
    }

    @UseGuards(JwtGuard)
    @Get('qrcode')
    async getQrCode(@Req() req: any, @Res() res: Response) {
        const user: User = await this.userService.findUserById(req.user.id);
        return await this.twoFactorAuthService.generateQrCode(res, user);
    }

    @UseGuards(JwtGuard)
    @Post('turn-on')
    async twoFactorAuthOn(
        @Req() req: any,
        @Body() twoFactorAuthCode: TwoFactorAuthCodeDto
    ) {
        const user: User = await this.userService.findUserById(req.user.id);

        const isCodeValidated = await this.twoFactorAuthService.isTwoFactorAuthCodeValid(
            twoFactorAuthCode.twoFactorAuthCode, user
        )

        if (!isCodeValidated) {
            throw new UnauthorizedException('Invalid otp code');
        }

		this.userService.updateUserById(user.id, {
			is2faEnabled : true,
            isOtpVerified : true,
		})
        return { message: '2fa turn on' }
    }

    @UseGuards(JwtGuard)
    @Post('turn-off')
    async twoFactorAuthOff(
        @Req() req: any,
        @Body() twoFactorAuthCode: TwoFactorAuthCodeDto
    ) {
        const user: User = await this.userService.findUserById(req.user.id);

        const isCodeValidated = await this.twoFactorAuthService.isTwoFactorAuthCodeValid(
            twoFactorAuthCode.twoFactorAuthCode, user
        )

        if (!isCodeValidated) {
            throw new UnauthorizedException('Invalid otp code');
        }

		this.userService.updateUserById(user.id, {
			is2faEnabled : false,
		})
        return { message: '2fa turn off' }
    }
}
