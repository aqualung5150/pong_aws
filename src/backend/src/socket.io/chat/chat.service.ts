import { HttpException, HttpStatus, Injectable, InternalServerErrorException, UseFilters } from '@nestjs/common';
import { ChatRoomStoreService, Room } from '../store/store.room.service';
import { ChatUserStoreService, User } from '../store/store.user.service';
import { ChatMessageStoreService, Message, DM } from '../store/store.message.service';
import { Namespace, Socket } from 'socket.io';
import * as bcrypt from 'bcrypt';
import {
	currRoomInfo,
	formedMessage,
	roomInfo,
	userInfo,
} from './types';
import { ChatSocket } from './types';

@Injectable()
export class ChatService {
	constructor(
		private storeUser: ChatUserStoreService,
		private storeRoom: ChatRoomStoreService,
		private storeMessage: ChatMessageStoreService,
	) { }

	initChatServer() {
		this.storeUser.saveUser(0, new User(0, 'Server_Admin'));
		this.storeRoom.saveRoom('DEFAULT', new Room()); //owner id 0 as server
	}

	updateChatScreen(client: Socket, clientId: number, roomname: string) {
		const user = this.storeUser.findUserById(clientId);
		const currRoomInfo = this.makeCurrRoomInfo(roomname);
		const roomMembers = this.makeRoomUserInfo(roomname);
		const roomInfo = this.makeRoomInfo(user.blocklist, user.joinlist);
		client.emit("sendRoomList", roomInfo);
		client.emit("sendRoomMembers", roomMembers);
		client.emit("sendCurrRoomInfo", currRoomInfo);
	}

	updateRoom(io: Namespace, roomname: string) {
		const currRoomInfo = this.makeCurrRoomInfo(roomname);
		const roomMembers = this.makeRoomUserInfo(roomname);
		io.in(roomname).emit("sendRoomMembers", roomMembers);
		io.in(roomname).emit("sendCurrRoomInfo", currRoomInfo);
	}

	async extractSocketsInRoomById(io: Namespace, targetId: number, roomname: string): Promise<ChatSocket[]> {
		const res = [];
		const sockets = await io.in(roomname).fetchSockets()
			.catch((error) => {
				return (error.message);
			});
		sockets.forEach((socket: ChatSocket) => {
			if (socket.userId === targetId)
				res.push(socket);
		})
		return (res);
	}

	makeMessageFormat(
		fromId: number,
		body: string,
		save: boolean,
		to?: string
	): formedMessage | null {
		let msg = null;
		if (save && to) {
			msg = new Message(fromId, body);
			const room = this.storeRoom.findRoom(to);
			if (room)
				room.messages.push(msg);
		}
		const format = {
			fromId: fromId,
			from: this.storeUser.getNicknameById(fromId),
			body: body,
			at: msg ? msg.at : Date.now()
		}
		return (format);
	}

	sendMsgToSocket(socket: ChatSocket, msg: formedMessage, roomname: string) {
		socket.emit("sendMessage", roomname, msg);
	}

	sendMsgToRoom(
		io: Namespace,
		fromId: number,
		to: string,
		body: string,
		save: boolean,
	): formedMessage {
		const format = this.makeMessageFormat(fromId, body, save, to);
		io.in(to).emit("sendMessage", to, format);
		return (format);
	}

	async handleNewConnection(io: Namespace, client: ChatSocket) {
		const userId = client.userId;
		client.join(`$${userId}`);
		let user: User = this.storeUser.findUserById(userId);
		if (user === undefined)
			user = this.storeUser.saveUser(userId, new User(userId, client.nickname));
		if (user.connected === false) {
			if (client.nickname != user.nickname) {
				user.nickname = client.nickname;
			}
			user.connected = true;
			client.emit("sendBlocklist", [...user.blocklist]);
			await this.updateUserStatus(io, userId, true);	//await...?
			if (client.nickname !== user.nickname)
				user.nickname = client.nickname;
		}
		this.userJoinRoomAct(io, client, userId, "DEFAULT");
	}

	async handleDisconnection(io: Namespace, client: ChatSocket): Promise<void> {
		const userId = client.userId;
		const isLastConn = (await io.in(`$${userId}`).fetchSockets()).length === 0;
		if (isLastConn) {
			const user = this.storeUser.findUserById(userId);
			user.connected = false;
			// this.userLeaveRooms(io, client, user.joinlist);
			await this.updateUserStatus(io, userId, false);
		}
	}

	async userJoinRoomAct(io: Namespace, client: any, clientId: number, roomname: string) {
		const user = this.storeUser.findUserById(clientId);
		if (!user.joinlist.has(roomname)) {
			const room = this.storeRoom.findRoom(roomname);
			if (!room) {
				client.emit("sendAlert", "[ Act Error ]", `${roomname} room is not exist`);
				return;
			}

			//bind room & user
			user.joinlist.add(roomname);
			room.addUserToUserlist(user.id);

			//save welcome message
			const body = `Welcome ${user.nickname} !`;
			this.sendMsgToRoom(io, 0, roomname, body, true);

			//send updateRoomMembers event to room
			const roomMembers = this.makeRoomUserInfo(roomname);
			io.in(roomname).emit("sendRoomMembers", roomMembers);
		}
		client.leave(client.currRoom)
		client.join(roomname);
		client.currRoom = roomname;
		this.updateChatScreen(client, clientId, roomname);
	}



	BanCheck(io: Namespace, client: ChatSocket, room: Room, roomname: string): boolean {
		if (room.isBanned(client.userId)) {
			client.emit("sendAlert", "[ Act Error ]", `You are banned from room ${roomname}`);
			return (false);
		}
		return (true);
	}

	async userJoinRoom(io: Namespace, client: ChatSocket, roomname: string, password?: string) {
		const userId = client.userId;
		let room = this.storeRoom.findRoom(roomname);
		if (room === undefined) {
			this.storeRoom.saveRoom(roomname, new Room(userId, password ? password : null));
			room = this.storeRoom.findRoom(roomname);
			this.userJoinRoomAct(io, client, userId, roomname);
		}
		else {
			if (room.isJoinning(userId)) {
				this.userJoinRoomAct(io, client, userId, roomname);
				return;
			}
			if (room.isPrivate) {
				client.emit("sendAlert", "[ Act Error ]", `${roomname} is Private Room`);
				return;
			}
			const pwExist = room.password ? true : false;
			if (pwExist) {
				if (password) {
					if (await room.isPassword(password)) {
						if (this.BanCheck(io, client, room, roomname))
							this.userJoinRoomAct(io, client, userId, roomname);
					}
					else
						client.emit("wrongPassword", roomname);
				}
				else
					client.emit("requestPassword", roomname);
			}
			else {
				if (this.BanCheck(io, client, room, roomname))
					this.userJoinRoomAct(io, client, userId, roomname);
			}
		}
	}

	async setPassword(io: Namespace, client: ChatSocket, roomname: string, password: string) {
		const room = this.storeRoom.findRoom(roomname);
		if (room.isOwner(client.userId)) {
			const saltOrRounds = 10;
			const hashedPassword = await bcrypt.hash(password, saltOrRounds);
			room.updatePassword(hashedPassword);
			client.emit("sendAlert", "[ Notice ]", "Password is updated");
		}
		else
			client.emit("sendAlert", "[ Act Error ]", "Only owner can change password");
	}

	setRoomStatus(io: Namespace, client: ChatSocket, roomname: string, toPrivate: boolean) {
		const room = this.storeRoom.findRoom(roomname);
		if (!room)
			throw new Error("Error : Room does not exist");
		if (room.isOwner(client.userId)) {
			if (toPrivate) {
				if (room.isPrivate)
					client.emit("sendAlert", "[ Alert ]", 'Room is already Private');
				else {
					room.isPrivate = true;
					io.to(roomname).emit("sendCurrRoomInfo", this.makeCurrRoomInfo(roomname));
				}
			}
			else {
				if (room.isPrivate) {
					room.isPrivate = false;
					io.to(roomname).emit("sendCurrRoomInfo", this.makeCurrRoomInfo(roomname));
				}
				else
					client.emit("sendAlert", "[ Alert ]", 'Room is already Public');
			}
		}
		else {
			client.emit("sendAlert", "[ Act Error ]", "Only owner can set room status");
		}
	}

	sendChat(io: Namespace, client: ChatSocket, to: string, body: string) {
		const room = this.storeRoom.findRoom(to);
		if (room === undefined) {
			throw new Error("Error : Room does not exist");
		}
		if (room.userlist.has(client.userId)) {
			if (!room.isMuted(client.userId)) {
				const msg = this.sendMsgToRoom(io, client.userId, to, body, true);
				//process sockets which has this room in their joinlist, but not currently in this room
				const users = this.storeUser.findAllUser().filter((user) => user.joinlist.has(to));
				if (users) {
					users.forEach((user) => {
						const roomInfo = this.makeRoomInfo(user.blocklist, user.joinlist);
						io.in(`$${user.id}`).except(to).emit("sendRoomList", roomInfo);
					})
				}
			}
			else
				client.emit("sendAlert", "[ Alert ]", `You are MUTED in ${to}`);
		}
		else {
			client.emit("sendAlert", "[ Act Error ]", `You are not joining in room ${to}`);
		}

	}

	userLeaveRoom(io: Namespace, client: ChatSocket, roomname: string) {
		const userId = client.userId;
		const room = this.storeRoom.findRoom(roomname);
		const thisUser = this.storeUser.findUserById(userId);
		if (room === undefined) {
			return ;
		}
		if (room.userlist.has(userId) && thisUser.joinlist.has(roomname)) {
			if (room.userlist.size == 1 && roomname != "DEFAULT") {
				room.clearRoom();
				this.storeRoom.deleteRoom(roomname);
				thisUser.joinlist.delete(roomname);
			}
			else {
				if (room.isOwner(userId)) {
					room.deleteUserFromUserlist(userId);
					const newOwner : number = room.userlist.values().next().value;
					room.updateOwner(newOwner);
					if (room.isOperator(newOwner))
						room.deleteUserFromOperators(newOwner);
					io.to(roomname).except(`$${userId}`).emit("sendCurrRoomInfo", this.makeCurrRoomInfo(roomname));
				}
				if (room.isOperator(userId)) {
					room.deleteUserFromOperators(userId);
					io.to(roomname).except(`$${userId}`).emit("sendCurrRoomInfo", this.makeCurrRoomInfo(roomname));
				}
				thisUser.joinlist.delete(roomname);
				room.deleteUserFromUserlist(userId);
				const body = `Good bye ${thisUser.nickname}`;
				this.sendMsgToRoom(io, 0, roomname, body, true);
				io.to(roomname).except(`$${userId}`).emit("sendRoomMembers", this.makeRoomUserInfo(roomname));
			}
		}
	}

	async userLeaveRoomAct(io: Namespace, targetId: number, roomname: string, alertMsg?: string) {
		await this.extractSocketsInRoomById(io, targetId, roomname)
			.then((res) => {
				res.forEach((socket) => {
					socket.leave(roomname);
					this.updateChatScreen(socket, targetId, "DEFAULT");
					if (alertMsg)
						socket.emit("sendAlert", "[ Alert ]", `${alertMsg}`)
				})
			})
	}

	userLeaveRooms(io: Namespace, client: ChatSocket, roomlist: Set<string>) {
		roomlist.forEach((room) => {
			this.userLeaveRoom(io, client, room);
		})
	}



	async kickUser(io: Namespace, client: ChatSocket, roomname: string, targetName: string) {
		const targetId = this.storeUser.getIdByNickname(targetName);
		const room = this.storeRoom.findRoom(roomname);
		if (this.checkActValidity(client, roomname, targetId, "kick")) {
			
			// delete user from room & room from user
			const targetUser = this.storeUser.findUserById(targetId);
			room.deleteUserFromUserlist(targetId);
			targetUser.joinlist.delete(roomname);

			await this.userLeaveRoomAct(io, targetId, roomname, `You are kicked out from ${roomname}`);

			if (room.isOperator(targetId)) {
				room.deleteUserFromOperators(targetId);
				io.to(roomname).emit("sendCurrRoomInfo", this.makeCurrRoomInfo(roomname));
			}
			const body = `${targetUser.nickname} is Kicked Out`;
			this.sendMsgToRoom(io, 0, roomname, body, false);
			io.to(roomname).emit("sendRoomMembers", this.makeRoomUserInfo(roomname));
		}
	}

	async banUser(io: Namespace, client: ChatSocket, roomname: string, targetName: string) {
		const targetId = this.storeUser.getIdByNickname(targetName);
		const room = this.storeRoom.findRoom(roomname);
		if (this.checkActValidity(client, roomname, targetId, "ban")) {
			room.addUserToBanlist(targetId);

			// delete user from room & room from user
			const targetUser = this.storeUser.findUserById(targetId);
			room.deleteUserFromUserlist(targetId);
			targetUser.joinlist.delete(roomname);

			await this.userLeaveRoomAct(io, targetId, roomname, `You are temporaily banned from ${roomname}`);

			if (room.isOperator(targetId)) {
				room.deleteUserFromOperators(targetId);
				io.to(roomname).emit("sendCurrRoomInfo", this.makeCurrRoomInfo(roomname));
			}
			const body = `${targetUser.nickname} is banned`;
			this.sendMsgToRoom(io, 0, roomname, body, false);
			io.to(roomname).emit("sendRoomMembers", this.makeRoomUserInfo(roomname));
		}
	}

	async muteUser(io: Namespace, client: ChatSocket, roomname: string, targetName: string) {
		const targetId = this.storeUser.getIdByNickname(targetName);
		const room = this.storeRoom.findRoom(roomname);
		if (!this.checkActValidity(client, roomname, targetId, "mute"))
			return;
		if (room.isMuted(targetId)) {
			const msg = this.makeMessageFormat(0, `${targetName} is already muted`, false);
			this.sendMsgToSocket(client, msg, roomname);
		}
		else {
			room.addUserToMutelist(targetId);
			let msg = this.makeMessageFormat(0, `${targetName} is now muted`, false);
			this.sendMsgToSocket(client, msg, roomname);
			const sockets = await this.extractSocketsInRoomById(io, targetId, roomname)
			sockets.forEach((socket) => {
				const msg = this.makeMessageFormat(0, `You are temporaily muted by ${this.storeUser.getNicknameById(client.userId)}`, false);
				this.sendMsgToSocket(socket, msg, roomname);
			})
			setTimeout(() => {
				room.deleteUserFromMutelist(targetId);
				sockets.forEach((socket) => {
					const msg = this.makeMessageFormat(0, `You are now unmuted`, false);
					this.sendMsgToSocket(socket, msg, roomname);
				})
			}, 20000);
		}
	}

	async blockUser(io: Namespace, client: ChatSocket, target: string) {
		if (client.nickname === target) {
			return ;
		}
		const thisUser = this.storeUser.findUserById(client.userId);
		const targetId = this.storeUser.getIdByNickname(target);
		(thisUser.addUserToBlocklist(targetId));
		const blocklist = [];
		thisUser.blocklist.forEach((user) =>
			blocklist.push(user));
		io.in(`$${client.userId}`).emit("sendBlocklist", blocklist);
		io.in(`$${client.userId}`).emit("updateBlocklist", targetId);
		const dmRoom = this.storeRoom.getDMRoomname(client.userId, targetId);
		const sockets = await io.in(dmRoom).fetchSockets()
			.then((res) => { return (res) })
			.catch((error) => {
				return (error.message);
			})
		sockets.forEach((socket: ChatSocket) => {
			if (socket.userId === client.userId)
				this.userJoinRoomAct(io, client, client.userId, 'DEFAULT');
		})
	}

	unblockUser(io: Namespace, client: ChatSocket, target: string) {
		if (client.nickname === target) {
			return;
		}
		const thisUser = this.storeUser.findUserById(client.userId);
		const targetId = this.storeUser.getIdByNickname(target);
		if (thisUser.blocklist.has(targetId)) {
			(thisUser.deleteUserFromBlockList(targetId));
			const blocklist = [];
			thisUser.blocklist.forEach((user) =>
				blocklist.push(user));
			io.in(`$${client.userId}`).emit("sendBlocklist", blocklist);
			io.in(`$${client.userId}`).emit("updateBlocklist", targetId);
			thisUser.joinlist.forEach((room) => {
				const currRoomInfo = this.makeCurrRoomInfo(room);
				const roomMembers = this.makeRoomUserInfo(room);
				io.in(room).emit("sendRoomMembers", roomMembers);
				io.in(room).emit("sendCurrRoomInfo", currRoomInfo);
			})
		}
	}

	addOperator(io: Namespace, client: ChatSocket, roomname: string, target: string) {
		const room = this.storeRoom.findRoom(roomname);
		if (!room.isOwner(client.userId))
			client.emit("sendAlert", "[ Act Error ]", "Only owner can add operator");
		else {
			const targetId = this.storeUser.getIdByNickname(target);
			if (room.isOperator(targetId))
				client.emit("sendAlert", "[ Act Error ]", "Target is already an operator");
			else {
				room.addUserToOperators(targetId);
				io.to(roomname).emit("sendCurrRoomInfo", this.makeCurrRoomInfo(roomname));
			}
		}

	}

	deleteOperator(io: Namespace, client: ChatSocket, roomname: string, target: string) {
		const room = this.storeRoom.findRoom(roomname);
		if (!room.isOwner(client.userId))
			client.emit("sendAlert", "[ Act Error ]", "Only Owner can delete operator");
		else {
			const targetId = this.storeUser.getIdByNickname(target);
			if (room.isOperator(targetId)) {
				room.deleteUserFromOperators(targetId);
				io.to(roomname).emit("sendCurrRoomInfo", this.makeCurrRoomInfo(roomname));
			}
			else {
				client.emit("sendAlert", "[ Act Error ]", "target is not an operator");
			}
		}

	}

	getAllRoomList(userId: number): roomInfo[] | null {
		const roomlist = [];
		const blocklist = this.storeUser.findUserById(userId)?.blocklist;
		this.storeRoom.rooms?.forEach((value, key) => {
			if (!value.isPrivate)
				roomlist.push(key);
		})
		if (!roomlist || !blocklist)
			return null;
		return (this.makeRoomInfo(blocklist, roomlist));
	}

	getUserRoomList(userId: number): roomInfo[] | null {
		const thisUser = this.storeUser.findUserById(userId);
		if (!thisUser)
			return null;
		return (this.makeRoomInfo(thisUser.blocklist, thisUser.joinlist));
	}


	getQueryRoomList(userId: number, query: string | null): roomInfo[] | null {
		if (query === null || query.length === 0)
			return ([]);
		const thisUser = this.storeUser.findUserById(userId);
		const roomlist = this.storeRoom.findQueryMatchRoomNames(query);
		if (!thisUser || !roomlist || roomlist.length === 0)
			return ([]);
		return (this.makeRoomInfo(thisUser.blocklist, roomlist));
	}


	fetchDM(io: Namespace, client: ChatSocket, target: string, body: string) {
		const from = client.userId;
		const to = this.storeUser.getIdByNickname(target);
		const message = new DM(from, to, body);
		const res = {
			fromId: from,
			from: this.storeUser.getNicknameById(from),
			toId: to,
			body: body,
			at: message.at
		};
		this.storeMessage.saveMessage(message);
		const dmRoom = this.storeRoom.getDMRoomname(from, to);
		io.to([dmRoom, `$${to}`]).emit("sendDM", this.storeUser.getNicknameById(to), res);
	}

	makeDMRoomMessages(client: ChatSocket, to: string): formedMessage[] | null {
		const toId = this.storeUser.getIdByNickname(to);
		const fromUser = this.storeUser.findUserById(client.userId);
		const toUser = this.storeUser.findUserById(toId);
		if (fromUser?.blocklist?.has(toId)) {
			client.emit("sendAlert", "[ Act Error ]", `You already blocked ${to}`)
			return null;
		}
		else if (toUser?.blocklist?.has(client.userId)) {
			client.emit("sendAlert", "[ Act Error ]", `You are blocked by ${toUser.nickname}`)
			return null;
		}
		else {
			const msg = this.storeMessage
				.findMessagesForUser(client.userId, toId)
				.map(message => ({
					from: this.storeUser.getNicknameById(message.from),
					fromId: message.from,
					to: this.storeUser.getNicknameById(message.to),
					toId: message.to,
					body: message.body,
					at: message.at
				}));
			return (msg);
		}
	}

	fetchUserToDMRoom(io: Namespace, client: ChatSocket, username: string) {
		const DMs = this.makeDMRoomMessages(client, username);
		const targetId = this.storeUser.getIdByNickname(username);
		if (DMs != null) {
			const dmRoom = this.storeRoom.getDMRoomname(client.userId, targetId);
			if (client.currRoom !== dmRoom) {
				client.leave(client.currRoom);
				client.join(dmRoom);
				client.currRoom = dmRoom;
			}
			client.emit("sendDMRoomInfo", username, targetId, DMs);
			if (client.userId !== targetId) {
				const DMRoomMembers = this.makeDMRoomUserInfo(client.userId, targetId);
				client.emit("sendRoomMembers", DMRoomMembers);
			}
			else {
				const DMRoomMembers = this.makeDMRoomUserInfo(client.userId);
				client.emit("sendRoomMembers", DMRoomMembers);
			}
			this.checkedDM(io, client.userId, targetId);
		}
	}

	checkedDM(io: Namespace, clientId: number, targetId: number) {
		io.in(`$${clientId}`).emit("userCheckedDM", targetId);
	}


	makeRoomInfo(blocklist: Set<number>, roomlist: string[] | Set<string>): roomInfo[] {
		const res = [];
		roomlist.forEach((room: string) => {
			const messages = this.storeRoom.findRoom(room).messages;
			const message = messages[messages.length - 1];
			res.push({
				roomname: room,
				fromId: message.from,
				lastMessage: message.body,
				at : message.at
			})
		})
		return res;
	}

	makeRoomUserInfo(roomname: string): userInfo[] {
		const room: Room = this.storeRoom.findRoom(roomname);
		if (!room || room.userlist.size === 0)
			return ([]);
		const userInfo = [];
		room.userlist.forEach((user) => {
			const target: User = this.storeUser.findUserById(user);
			userInfo.push({
				id: user,
				nickname: target.nickname,
				isGaming: target.isGaming,
				isConnected: target.connected,
			})
		})
		return (userInfo);
	}

	makeDMRoomUserInfo(fromId: number, toId?: number): userInfo[] {
		const fromUser = this.storeUser.findUserById(fromId);
		const userInfo = [];
		if (toId) {
			const toUser = this.storeUser.findUserById(toId);
			userInfo.push({
				id: toUser.id,
				nickname: toUser.nickname,
				isGaming: toUser.isGaming,
				isConnected: toUser.connected,
			})
		}
		userInfo.push({
			id: fromUser.id,
			nickname: fromUser.nickname,
			isGaming: fromUser.isGaming,
			isConnected: fromUser.connected,
		})
		return (userInfo);
	}

	mappingMessagesUserIdToNickname(messages: Message[]): formedMessage[] {
		const res = [];
		messages.forEach((msg) => {
			res.push({
				fromId: msg.from,
				from: `${this.storeUser.getNicknameById(msg.from)}`,
				body: msg.body,
				at: msg.at
			})
		})
		return (res);
	}

	makeCurrRoomInfo(roomname: string): currRoomInfo {
		const room = this.storeRoom.findRoom(roomname);
		if (!room)
			throw new Error(`[makeCurrRoomInfo] : ${roomname} room is not exist`);
		let owner: string | null;
		if (room.owner === 0)
			owner = null;
		else
			owner = this.storeUser.getNicknameById(room.owner);
		const operatorList = [];
		room.operators.forEach((user) => {
			operatorList.push(this.storeUser.getNicknameById(user));
		})
		const res = {
			roomname: roomname,
			owner: owner,
			operators: operatorList,
			messages: this.mappingMessagesUserIdToNickname(room.messages),
			isPrivate: room.isPrivate,
			isProtected: room.password ? true : false
		}
		return (res)
	}

	checkActValidity(client: ChatSocket, roomname: string, target: number, act: string): boolean {
		const actor = client.userId;
		if (actor === target) {
			client.emit("sendAlert", "[ ACT ERROR ]", `you can't ${act} yourself`)
			return (false);
		}
		const room = this.storeRoom.findRoom(roomname);
		if (room === undefined) {
			client.emit("sendAlert", "[ ACT ERROR ]", `(${act}) Room does not exist`)
			return (false);
		}
		const user = this.storeUser.findUserById(actor);
		if (user === undefined || !user.joinlist.has(roomname)) {
			client.emit("sendAlert", "[ ACT ERROR ]", `(${act}) invalid Actor`)
			return (false);
		}
		if (!room.isOwner(user.id) && !room.isOperator(user.id)) {
			client.emit("sendAlert", "[ ACT ERROR ]", `You are not authorized to ${act}`)
			return (false);
		}
		const targetName = this.storeUser.getNicknameById(target);
		if (target === 0 || targetName === undefined) {
			client.emit("sendAlert", "[ ACT ERROR ]", `(${act}) Target does not exist`)
			return (false);
		}
		else if (!room.isJoinning(target)) {
			client.emit("sendAlert", "[ ACT ERROR ]", `${targetName} is not joining this room`)
			return (false);
		}
		else if (room.isOwner(target)) {
			client.emit("sendAlert", "[ ACT ERROR ]", `${targetName} is the Owner`)
			return (false);
		}
		else if (room.isOperator(target) && !room.isOwner(actor)) {
			client.emit("sendAlert", "[ ACT ERROR ]", `Only owner can ${act} Operator`)
			return (false);
		}
		return (true);
	}

	getAllUserInfo(userId: number): userInfo[] | null {
		const thisUser = this.storeUser.findUserById(Number(userId));
		if (!thisUser) {
			return null;
		}
		const blocklist = thisUser.blocklist;
		const users = this.storeUser.findAllUser();
		const res = [];
		users?.forEach((user) => {
			res.push({
				id: user.id,
				nickname: user.nickname,
				isGaming: user.isGaming,
				isConnected: user.connected,
				isBlocked: blocklist.has(user.id) ? true : false
			})
		});
		return (res);
	}

	getUserInfoById(userId: number, targetId: number): userInfo {
		const target = this.storeUser.findUserById(Number(targetId));
		return ({
			id: Number(targetId),
			nickname: target.nickname,
			isGaming: target.isGaming,
			isConnected: target.connected,
			isBlocked: this.storeUser.findUserById(userId).blocklist.has(Number(targetId)) ? true : false
		});
	}

	async triggerWindowUpdate(io: Namespace, user: User) {
		user.joinlist.forEach((room) => {
			const currRoomInfo = this.makeCurrRoomInfo(room);
			const roomMembers = this.makeRoomUserInfo(room);
			io.in(room).emit("sendRoomMembers", roomMembers);
			io.in(room).emit("sendCurrRoomInfo", currRoomInfo);
		})
		const dmRooms = [];
		io.adapter.rooms.forEach(async (_, key) => {
			if (this.storeRoom.isDMRoom(key)){
				const fromId = this.storeRoom.getFromIdFromDMRoom(key, user.id);
				if (fromId){
					const sockets = await io.in(key).fetchSockets()
							.catch((error) => { return error });
					sockets.forEach((socket : ChatSocket) => {
						this.fetchUserToDMRoom(io, socket, user.nickname);
					})
				}
				else {
					const toId = this.storeRoom.getToIdFromDMRoom(key, user.id);
					if (toId){
						const sockets = await io.in(key).fetchSockets()
									.catch((error) => { return error });
						sockets.forEach((socket : ChatSocket) => {
							this.fetchUserToDMRoom(io, socket, this.storeUser.getNicknameById(Number(toId)));
						})
					}
				}			
			}
		});
	}

	async userChangeNick(io: Namespace, clientId: number, newNick: string) {
		const user = this.storeUser.findUserById(clientId);
		user.nickname = newNick;
		await this.triggerWindowUpdate(io, user);
	}

	async userChangeAvatar(io: Namespace, clientId: number) {
		const user = this.storeUser.findUserById(clientId);
		await this.triggerWindowUpdate(io, user);
	}


	async updateUserStatus(io: Namespace, userId: number, isConnected: boolean) {
		const user = this.storeUser.findUserById(userId);
		io.emit("updateUserStatus", userId, isConnected);
		await this.triggerWindowUpdate(io, user);
	}
}
