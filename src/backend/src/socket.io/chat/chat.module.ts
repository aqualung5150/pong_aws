import { Module } from '@nestjs/common';
import { ChatService } from './chat.service';
import { ChatGateway } from './chat.gateway';
import { JwtModule } from '@nestjs/jwt';
import { StoreModule } from 'src/socket.io/store/store.module';

@Module({
	imports : [
		StoreModule,
		JwtModule
	],
	providers: [
		ChatService,
		ChatGateway, 
	],
	exports: [
		ChatGateway
	]
})
export class ChatModule {}
