import { IsNotEmpty, IsString } from 'class-validator';

export class KeydownPayload {
    @IsNotEmpty()
    @IsString()
    roomName: string;
    
    @IsNotEmpty()
    @IsString()
    key: string;
}