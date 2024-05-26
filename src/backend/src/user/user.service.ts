import { Injectable, HttpException, HttpStatus, StreamableFile, ConsoleLogger } from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';
import { Prisma, User } from '@prisma/client';
import { join } from 'path';
import { createReadStream } from 'fs';
import * as fs from 'fs';
import { ChatGateway } from 'src/socket.io/chat/chat.gateway';
import { GameGateway } from 'src/socket.io/game/game.gateway';
import { UpdateFriendDto } from './dto/update-friend.dto';
import { Login } from 'src/auth/types';

@Injectable()
export class UserService {
	constructor(
		private readonly prisma: PrismaService,
		private readonly chatGateway: ChatGateway,
		private readonly gameGateway: GameGateway
	) { }

	async createUser(data: Prisma.UserCreateInput): Promise<Login> {
		while (!data.nickname) {
			data.nickname = `user_${Math.floor(Math.random() * 1000)}`;
			const isUnique = await this.prisma.user.findUnique({
				where: { nickname: data.nickname },
				select: { nickname: true }
			});
			if (isUnique)
				data.nickname = null;
		}
		const res = await this.prisma.user.upsert({
			where: {
				// name: data.name,
				// id: data.id,
				email: data.email,
			},
			update: {},
			create: {
				name: data.name,
				// id: data.id,
				nickname: data.nickname,
				email: data.email
			},
			select : {
				id : true,
				name: true, //
				email : true,
				nickname : true,
				is2faEnabled: true,
			}
		})
		const isNewUser = data.nickname === res.nickname? true : false;
		const returnData = {
			id: res.id,
			name: res.name,
			email: res.email,
			nickname: res.nickname,
			is2faEnabled: res.is2faEnabled,
			isNewUser: isNewUser,
		}
		return (returnData);
	}

	async findUserById(userId: number): Promise<any | undefined> {
		const user = await this.prisma.user.findUnique({
			where: {
				id: userId,
			},
		})

		return user
	}

	async getAllUser(): Promise<object[]> {
		const res = await this.prisma.user.findMany({
			select: {
				id: true,
				nickname: true,
				avatar: true,
				score: true,
				lastLogin: true
			},
			orderBy: { lastLogin: 'desc' },
			where : { id : { not : 0 }}
		});
		return (res);
	}

	async getUserById(id: number): Promise<object> {
		return await this.prisma.user.findUniqueOrThrow({
			where: { id: id },
			select: {
				id: true,
				nickname: true,
				email: true,
				avatar: true,
				score: true,
				lastLogin: true,
				_count: {
					select: {
						asWinner: true,
						asLoser: true,
					}
				}
			}
		}).then((res) => {
			return (res);
		})
		.catch((error) => {
			return { message: 'An error occurred', error: error.message };
		});
	}

	async updateUserById(
		id: number,
		data: Prisma.UserUpdateInput,
		file?: Express.Multer.File) {
		let oldAvatar: string;
		if (file) {
			oldAvatar = await this.prisma.user.findUniqueOrThrow({
				where: { id },
				select: { avatar: true }
			}).then((res) => { return res.avatar })
		}
		return await this.prisma.user.update({
			where: { id: id },
			data: {
				...data,
				id: undefined,
				friends: undefined,
				avatar: file != null ? file.filename.toString() : undefined,
			}
		}).then((res) => {
			if (file) {
				this.chatGateway.updateUserAvatar(id, file.path.toString() as string);
				if (oldAvatar != "default.png") {
					fs.unlink('/photo/' + oldAvatar, (err) => {
						//file erase failure
						if (err)
							console.log(err);
					});
				}
			}
			if (data.nickname) {
				this.chatGateway.updateUserNick(id, data.nickname as string);
				this.gameGateway.updateUserNick(id, data.nickname as string);
			}
			return (res);
		}).catch((error) => {
			if (error instanceof Prisma.PrismaClientValidationError) {
				return { error: "Validation Error" };
			}
			else
				return { code: error.code, error: error.message };
		});
	}

	async getUserFriendsListById(id: number): Promise<object> {
		return await this.prisma.user.findUniqueOrThrow({
			where: { id: id }
		})
		.then((res) => { return res.friends })
		.catch((error) => {
			return { message: '', error: error.message };
		})
	}

	async getUserFriendsById(id: number): Promise<object> {
		return await this.prisma.user.findUniqueOrThrow({
			where: { id: id },
		})
		.then((user) => {
			return Promise.all(
				user.friends.map((element) => {
					return this.getUserById(element);
				})
			);
		})
		.then((friendList) => {
			return { friendList };
		})
		.catch((error) => {
			return { message: '', error: error.message };
		});
	}

	async updateFriendsById(id: number, data: UpdateFriendDto): Promise<object> {
		if (id == data.friend)
			throw new HttpException(
				"I am a good friend of myself...",
				HttpStatus.BAD_REQUEST
			);
		const user = await this.prisma.user.findUniqueOrThrow({
			where: { id },
			select: { friends: true }
		});

		if (data.isAdd == true) {
			await this.prisma.user.findUniqueOrThrow({
				where: { id: data.friend },
			});
			if (user.friends.includes(data.friend))
				throw new HttpException(
					"Already In!",
					HttpStatus.BAD_REQUEST
				);
			return this.prisma.user.update({
				where: { id },
				data: {
					friends: {
						push: data.friend,
					}
				}
			}).then((res) => {
				this.chatGateway.updateUserFriend(id, data.friend, data.isAdd);
				return (res);
			})
		}
		else {
			if (!user.friends.includes(data.friend))
				throw new HttpException(
					"Not in the list",
					HttpStatus.BAD_REQUEST,
				);
			return await this.prisma.user.update({
				where: { id },
				data: {
					friends: {
						set: user.friends.filter((num) => num !== data.friend),
					}
				}
			});
		}
	}

	async getUserMatchHistoryById(id: number): Promise<object[]> {
		return await this.prisma.matchHistory.findMany({
			where: {
				OR: [{ winnerId: id }, { loserId: id }]
			},
			select: {
				winner: {
					select: {
						id: true,
						nickname: true,
						avatar: true
					}
				},
				loser: {
					select: {
						id: true,
						nickname: true,
						avatar: true
					}
				},
				createdTime: true
			},
			orderBy: { createdTime: 'desc' }
		})
	}

	async getUserImageById(id: number) {
		const fileName = await this.prisma.user.findUnique({
			where: { id },
			select: { avatar: true },
		}).then((res) => {
			return res.avatar
		});
		if (!fileName)
			return null;
		const file = createReadStream(join('/photo/' + fileName));
		return new StreamableFile(file);
	}
}