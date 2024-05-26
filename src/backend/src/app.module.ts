import { Module } from '@nestjs/common';
// import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { TwoFactorAuthModule } from './two-factor-auth/two-factor-auth.module';
import { PrismaService } from './prisma.service';
import { UserModule } from './user/user.module';
import { MatchModule } from './match/match.module';
import { ChatModule } from './socket.io/chat/chat.module';
import { GameModule } from './socket.io/game/game.module';

@Module({
  imports: [
		AuthModule,
		TwoFactorAuthModule,
		UserModule,
		MatchModule,
		ChatModule,
		GameModule,
	],
  // imports: [ConfigModule.forRoot(), AuthModule, UserAuthModule, TwoFactorAuthModule],
  controllers: [AppController],
  providers: [AppService, PrismaService],
})
export class AppModule {}
