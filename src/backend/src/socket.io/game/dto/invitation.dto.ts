import { IsNotEmpty, IsNumber, IsString } from 'class-validator';

export class Invitation {
    @IsNotEmpty()
    @IsString()
    from: string;

    @IsNotEmpty()
    @IsNumber()
    fromId: number;

    @IsNotEmpty()
    @IsString()
    to: string;

    @IsNotEmpty()
    @IsNumber()
    toId: number;
    
    @IsNotEmpty()
    @IsString()
    mode: string;
}