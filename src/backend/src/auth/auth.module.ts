import { Module, forwardRef } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { HttpModule } from '@nestjs/axios';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './jwt.strategy';
import { JwtRefreshStrategy } from './jwt-refresh.strategy';
import { TwoFactorAuthService } from 'src/two-factor-auth/two-factor-auth.service';
import { TwoFactorAuthModule } from 'src/two-factor-auth/two-factor-auth.module';
import { PrismaService } from 'src/prisma.service';
import { UserModule } from 'src/user/user.module';
import { ChatModule } from 'src/socket.io/chat/chat.module';

@Module({
  imports: [
	UserModule,
    forwardRef(()=>TwoFactorAuthModule),
    HttpModule,
    JwtModule.register({
          secret: process.env.JWT_ACCESS_TOKEN_SECRET,
          signOptions: {
              expiresIn: process.env.JWT_ACCESS_EXPIRATION_TIME,
          },
    }),
    ChatModule
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    TwoFactorAuthService,
    JwtStrategy,
    JwtRefreshStrategy,
    PrismaService,
  ],
})
export class AuthModule {}
