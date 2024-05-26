import { Module, forwardRef } from '@nestjs/common';
import { TwoFactorAuthService } from './two-factor-auth.service';
import { TwoFactorAuthController } from './two-factor-auth.controller';
import { AuthService } from 'src/auth/auth.service';
import { AuthModule } from 'src/auth/auth.module';
import { PrismaService } from 'src/prisma.service';
import { UserService } from 'src/user/user.service';
import { JwtModule } from '@nestjs/jwt';
import { HttpModule } from '@nestjs/axios';
import { ChatModule } from 'src/socket.io/chat/chat.module';
import { GameModule } from 'src/socket.io/game/game.module';

@Module({
  imports: [
    forwardRef(()=>AuthModule),
    HttpModule,
    JwtModule.register({
      secret: process.env.JWT_ACCESS_TOKEN_SECRET,
      signOptions: {
          expiresIn: process.env.JWT_ACCESS_EXPIRATION_TIME,
      },
    }),
    ChatModule,
    GameModule
  ],
  providers: [
    TwoFactorAuthService,
    AuthService,
	  UserService,
    PrismaService,
  ],
  controllers: [TwoFactorAuthController],
  exports: [TwoFactorAuthService]
})
export class TwoFactorAuthModule {}
