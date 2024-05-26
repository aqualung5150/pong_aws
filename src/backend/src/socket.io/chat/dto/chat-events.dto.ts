import { IsNotEmpty, IsNumber, IsOptional, IsString, IsNumberString } from 'class-validator';
import { IntersectionType } from '@nestjs/mapped-types';

//why not type then class?
export class MessageDto {
    @IsNotEmpty()
	@IsString()
	to : string;
	
    @IsNotEmpty()
	@IsString()
	body : string;
}

export class RoomDto {
	@IsNotEmpty()
	@IsString()
	roomname : string;

	@IsString()
	@IsOptional()
	password : string;
}

export class TargetDto {
	@IsNotEmpty()
	@IsString()
	target : string;
}

export class NullableTargetDto {
	@IsOptional()
	@IsString()
	target : string;
}

export class UserInfoDto {
	@IsOptional()
	@IsNumber()
	userId : number;

	@IsOptional()
	@IsNumber()
	targetId : number;
}

export class RoomEventDto extends IntersectionType (
	RoomDto,
	TargetDto
) {}