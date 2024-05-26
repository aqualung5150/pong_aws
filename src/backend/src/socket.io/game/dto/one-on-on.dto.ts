import { IsNotEmpty, IsString } from 'class-validator';

export class OneOnOnePayload {
    @IsNotEmpty()
    @IsString()
    from: string;

    @IsNotEmpty()
    @IsString()
    to: string;
    
    @IsNotEmpty()
    @IsString()
    mode: string;
}