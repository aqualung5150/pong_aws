import { Injectable } from '@nestjs/common';
import { authenticator } from 'otplib';
import { toFileStream } from 'qrcode';
import { Response } from 'express';
import { User } from '@prisma/client';
import { UserService } from 'src/user/user.service';

@Injectable()
export class TwoFactorAuthService {
    constructor( private userService : UserService ) {}

    async generateQrCode(stream: Response, user: User): Promise<any> {
        if (user.isOtpVerified) {
            return stream.send({
                message: 'you already have otp secret',
            })
        }
        const secret = authenticator.generateSecret();

		this.userService.updateUserById(user.id, {
			otpSecret : secret,
		})

        const otpAuthUrl = authenticator.keyuri(user.email, 'seunchoi-2fa', secret);
        return toFileStream(stream, otpAuthUrl);
    }

    async isTwoFactorAuthCodeValid(twoFactorAuthCode: string, user: User) {
        if(!user.otpSecret) {
            return false;
        }

        return authenticator.verify({
            token: twoFactorAuthCode,
            secret: user.otpSecret,
        });
    }
}
