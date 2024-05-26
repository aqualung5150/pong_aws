import { Test, TestingModule } from '@nestjs/testing';
import { ChatRoomStoreService } from './store.room.service';

describe('ChatRoomStoreService', () => {
  let service: ChatRoomStoreService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [ChatRoomStoreService],
    }).compile();

    service = module.get<ChatRoomStoreService>(ChatRoomStoreService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
