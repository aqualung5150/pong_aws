import { Module } from '@nestjs/common';
import { ChatMessageStoreService } from './store.message.service';
import { ChatUserStoreService } from './store.user.service';
import { ChatRoomStoreService } from './store.room.service';

@Module({
	providers : [
		ChatMessageStoreService,
		ChatUserStoreService,
		ChatRoomStoreService,
	],
	exports : [
		ChatMessageStoreService,
		ChatUserStoreService,
		ChatRoomStoreService
	]
})
export class StoreModule {}
