import { Test, TestingModule } from '@nestjs/testing';
import { ChatUserStoreService } from './store.user.service';

describe('ChatUserStoreService', () => {
  let service: ChatUserStoreService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [ChatUserStoreService],
    }).compile();

    service = module.get<ChatUserStoreService>(ChatUserStoreService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
