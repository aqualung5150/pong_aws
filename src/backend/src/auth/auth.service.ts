import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { lastValueFrom } from 'rxjs';
import { HttpService } from '@nestjs/axios';
import { UserService } from 'src/user/user.service';
import { User } from '@prisma/client';
import { JwtPayload } from './types';

@Injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name);
    constructor(
        private jwtService: JwtService,
		private userService : UserService,
        private httpService: HttpService,
    ) {}

    async getUserFromApi(code: string): Promise<any> {
        // const tokenReq = this.httpService.post("https://api.intra.42.fr/oauth/token", {
        const tokenReq = this.httpService.post("https://oauth2.googleapis.com/token", {
            grant_type: process.env.OAUTH_GOOGLE_GRANT_TYPE,
            code: code,
            client_id: process.env.OAUTH_GOOGLE_ID,
            client_secret: process.env.OAUTH_GOOGLE_SECRET,
            redirect_uri: process.env.OAUTH_GOOGLE_REDIRECT,
            // scope: "public",
        })

        const tokenData = await lastValueFrom(tokenReq);

        const access_token = tokenData.data.access_token;

        this.logger.debug(access_token);

        const userReq = this.httpService.get('https://www.googleapis.com/oauth2/v3/userinfo', {
            headers: { Authorization: `Bearer ${access_token}` },
        });

        const userData = await lastValueFrom(userReq);

        return userData.data;
    }

    async generateAccessToken(payload: JwtPayload): Promise<string> {

        return await this.jwtService.signAsync({
            id: payload.id,
            name: payload.name,
            email: payload.email,
        });
    }

    async generateRefreshToken(payload: JwtPayload): Promise<string> {
        return await this.jwtService.signAsync(
            {
                id: payload.id,
                name: payload.name,
                email: payload.email
            },
            {
            secret: process.env.JWT_REFRESH_TOKEN_SECRET,
            expiresIn: process.env.JWT_REFRESH_EXPIRATION_TIME,
            }
        );
    }

    async getHashedRefreshToken(refreshToken: string) {
        // 토큰 값을 그대로 저장하기 보단, 암호화를 거쳐 데이터베이스에 저장한다. 
        // bcrypt는 단방향 해시 함수이므로 암호화된 값으로 원래 문자열을 유추할 수 없다. 
        const signatue = refreshToken.split('.')[2];
        const saltOrRounds = 10;
        const hashedRefreshToken = await bcrypt.hash(signatue, saltOrRounds);
        return hashedRefreshToken;
    }

	async getUserIfRefreshTokenMatches(refreshToken: string, userId: number): Promise<User>
    {
        const user = await this.userService.findUserById(userId);

        if (!user) {
            throw new UnauthorizedException("no such user in database");
        }

        if (!user.refreshToken) {
            throw new UnauthorizedException("no refresh token on user");
        }

        const signatue = refreshToken.split('.')[2];

        const isMatched = await bcrypt.compare(signatue, user.refreshToken);

        if (isMatched) {
            return user;
        }
    }
}
