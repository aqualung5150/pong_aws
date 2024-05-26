import { Body, Controller, Get, UseGuards, HttpException, HttpStatus, Param, ParseIntPipe, Patch, Post, Req, UseInterceptors, UploadedFile, ParseFilePipeBuilder, Res, StreamableFile, Logger } from '@nestjs/common';
import { UserService } from './user.service';
import { Prisma } from '@prisma/client';
import { JwtGuard } from 'src/auth/guards/jwt.guard';
import { Express } from 'express';
import { FileInterceptor } from '@nestjs/platform-express';
import { join } from 'path';
import { createReadStream } from 'fs';
import { UpdateFriendDto } from './dto/update-friend.dto';

@Controller('user')
export class UserController {
	private readonly logger = new Logger(UserController.name);
	constructor(private readonly userService: UserService) {}

	@UseGuards(JwtGuard)
	@Get('/')
	getAllUser() : Promise<object[]> {
		return (this.userService.getAllUser());
	}

	@UseGuards(JwtGuard)
	@Get(':id')
	getOneUser(@Param('id', ParseIntPipe) id : number) : Promise<object> {
		return (this.userService.getUserById(id));
	}

	@UseGuards(JwtGuard)
	@UseInterceptors(FileInterceptor(
		'avatar',
		{
			dest: '/photo',
		})
	)
	@Post(':id')
	async updateUserAvatar(
		@Req() req : any,
		@Param('id', ParseIntPipe) id : number,
		@UploadedFile(
			new ParseFilePipeBuilder()
			.addFileTypeValidator({
				fileType: '.(jpeg|jpg|png|gif)',
			})
			.build({
				fileIsRequired: true
			})
		) file : Express.Multer.File,
		@Body() data : Prisma.UserUpdateInput,
		) : Promise<any>{
		if (req.user.id != id)
			throw new HttpException("Unauthorized action", HttpStatus.BAD_REQUEST);
		return this.userService.updateUserById(id, data, file);
	}

	@UseGuards(JwtGuard)
	@Patch(':id')
	async updateUser(
		@Param('id', ParseIntPipe) id : number,
		@Body() data : Prisma.UserUpdateInput) : Promise<Object> {
		return this.userService.updateUserById(id, data);
	}

	@UseGuards(JwtGuard)
	@Get(':id/friend')
	async getUserFriends(@Param('id', ParseIntPipe) id : number) : Promise<object> {
		return this.userService.getUserFriendsById(id);
	}

	@UseGuards(JwtGuard)
	@Patch(':id/friend')
	updateUserFriends(
		@Req() req : any,
		@Param('id', ParseIntPipe) id : number,
		@Body() data : UpdateFriendDto
		) : Promise<object> {
			if (req.user.id != id)
				throw new HttpException("Unauthorized action", HttpStatus.BAD_REQUEST);
			return this.userService.updateFriendsById(id, data);
	}


	@UseGuards(JwtGuard)
	@Get(':id/matchhistory')
	async getUserMatchHistory(@Param('id', ParseIntPipe) id : number)
		 : Promise<object[]> {
			return this.userService.getUserMatchHistoryById(id);
	}

	@Get(':id/photo')
	async streamUserImage(@Param('id', ParseIntPipe) id : number) {
		return await this.userService.getUserImageById(id)
			.catch((error) => {
				throw new HttpException(error.message, HttpStatus.NOT_FOUND);
			})
	}
}

@UseGuards(JwtGuard)
@Controller('photo/:img')
export class avatarController {
	constructor(private readonly userService: UserService) {}

	@Get()
	getAvatar(@Param('img') img : string) : StreamableFile {
		const file = createReadStream(join('/photo/' + img));
		return new StreamableFile(file);
	}
}