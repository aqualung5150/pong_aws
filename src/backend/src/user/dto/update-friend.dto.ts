import { Type } from 'class-transformer';
import { IsBoolean, IsNotEmpty, IsNumber } from 'class-validator';

export class UpdateFriendDto {
  @IsNotEmpty()
  @IsNumber()
  friend: number;
  
  @IsNotEmpty()
  @IsBoolean()
  isAdd: boolean;
}