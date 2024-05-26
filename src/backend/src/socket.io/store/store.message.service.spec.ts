import { Test, TestingModule } from '@nestjs/testing';
import { ChatMessageStoreService } from './store.message.service';

describe('ChatMessageStoreService', () => {
  let service: ChatMessageStoreService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [ChatMessageStoreService],
    }).compile();

    service = module.get<ChatMessageStoreService>(ChatMessageStoreService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
