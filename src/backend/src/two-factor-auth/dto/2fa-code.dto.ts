import { IsNotEmpty, IsNumber, IsString } from 'class-validator';

export class TwoFactorAuthCodeDto {
  @IsNotEmpty()
  @IsNumber()
  id: number;

  @IsNotEmpty()
  @IsString()
  twoFactorAuthCode: string;
}