import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { PrismaService } from 'src/prisma.service';
import { UserController, avatarController } from './user.controller';
import { JwtGuard } from 'src/auth/guards/jwt.guard';
import { ChatModule } from 'src/socket.io/chat/chat.module';
import { StoreModule } from 'src/socket.io/store/store.module';
import { JwtModule } from '@nestjs/jwt';
import { GameModule } from 'src/socket.io/game/game.module';

@Module({
	imports: [
		GameModule,
		ChatModule,
		StoreModule,
		JwtModule
	],
	controllers: [UserController, avatarController],
	providers: [
		UserService,
		PrismaService,
		JwtGuard,
	],
	exports: [UserService]
})
export class UserModule {}
