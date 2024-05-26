import { Logger, ValidationPipe, UsePipes, UseFilters } from '@nestjs/common';
import {
	ConnectedSocket,
	OnGatewayConnection,
	OnGatewayDisconnect,
	OnGatewayInit,
	SubscribeMessage,
	WebSocketGateway,
	WebSocketServer,
} from '@nestjs/websockets';
import { Namespace } from 'socket.io';
import { ChatService } from './chat.service';
import { ChatSocket } from './types';
import { MessageDto, NullableTargetDto, RoomDto, RoomEventDto, TargetDto, UserInfoDto } from './dto/chat-events.dto';
import { WsExceptionFilter } from '../ws-exception.filter';

@UsePipes(new ValidationPipe({
	forbidNonWhitelisted: true,
	whitelist: true,
	transform: true,
	transformOptions : { enableImplicitConversion: true }
  }))
@UseFilters(WsExceptionFilter)
@WebSocketGateway({
	namespace: 'chat',
	pingInterval: 250000,
	pingTimeout: 250000,
})
export class ChatGateway
	implements OnGatewayConnection, OnGatewayDisconnect, OnGatewayInit {
	@WebSocketServer() io: Namespace;
	private readonly logger = new Logger(ChatGateway.name);
	constructor(private chatService: ChatService) { }

	afterInit() {
		this.chatService.initChatServer();
	}

	async handleConnection(@ConnectedSocket() client: ChatSocket) {
		this.logger.log(`Client Connected : ${client.nickname}, ${client.id}`);

		client.onAny((any: any) => {
			this.logger.log(`From Client ${client.nickname}, ${client.id}, event : ${any}`);
		})
		await this.chatService.handleNewConnection(this.io, client);

	}

	async handleDisconnect(@ConnectedSocket() client: ChatSocket) {
		this.logger.log(client.nickname + ", " + client.id + ' is leaving');
		await this.chatService.handleDisconnection(this.io, client);
	}


	@SubscribeMessage('sendChatMessage')
	handleSendChat(client: ChatSocket, payload: MessageDto) {
		this.chatService.sendChat(
			this.io, client, payload.to, payload.body
		);
	}

	@SubscribeMessage('sendDirectMessage')
	handleSendDM(client: ChatSocket, payload: MessageDto) {
		this.chatService.fetchDM(
			this.io, client, payload.to, payload.body
		);
	}

	@SubscribeMessage('selectRoom')
	handleEnterRoom(client: ChatSocket, payload: RoomDto) {
		this.chatService.userJoinRoom(
			this.io, client, payload.roomname
		);
	}

	@SubscribeMessage('selectDMRoom')
	handleEnterDMRoom(client: ChatSocket, payload: TargetDto) {
		this.chatService.fetchUserToDMRoom(
			this.io, client, payload.target
		);
	}

	@SubscribeMessage('sendRoomLeave')
	handleLeaveRoom(client: ChatSocket, payload: RoomDto) {
		this.chatService.userLeaveRoom(this.io, client, payload.roomname);
		this.chatService.userLeaveRoomAct(this.io, client.userId, payload.roomname);
	}

	@SubscribeMessage('sendRoomPass')
	handleEnterRoomWithPassword(client: ChatSocket, payload: RoomDto) {
		this.chatService.userJoinRoom(
			this.io, client, payload.roomname, payload.password
		);
	}

	@SubscribeMessage('setRoomPass')
	async handleSetRoomPass(client: ChatSocket, payload: RoomDto) {
		await this.chatService.setPassword(
			this.io, client, payload.roomname, payload.password
		);
	}

	@SubscribeMessage('setRoomPrivate')
	handleSetRoomPrivate(client: ChatSocket, payload: RoomDto) {
		this.chatService.setRoomStatus(
			this.io, client, payload.roomname, true
		);
	}
	@SubscribeMessage('setRoomPublic')
	handleSetRoomPulbic(client: ChatSocket, payload: RoomDto) {
		this.chatService.setRoomStatus(
			this.io, client, payload.roomname, false
		);
	}

	@SubscribeMessage('userCheckedDM')
	handleCheckDM(client: ChatSocket, target: UserInfoDto) {
		this.chatService.checkedDM(
			this.io, client.userId, target.targetId
		);
	}

	@SubscribeMessage('blockUser')
	handleBlockUser(client: ChatSocket, payload: TargetDto) {
		this.chatService.blockUser(
			this.io, client, payload.target
		);
	}

	@SubscribeMessage('unblockUser')
	handleUnblockUser(client: ChatSocket, payload: TargetDto) {
		this.chatService.unblockUser(
			this.io, client, payload.target
		);
	}

	@SubscribeMessage('kickUser')
	handleKickUser(client: ChatSocket, payload: RoomEventDto) {
		this.chatService.kickUser(
			this.io, client, payload.roomname, payload.target
		);
	}

	@SubscribeMessage('banUser')
	handleBanUser(client: ChatSocket, payload: RoomEventDto) {
		this.chatService.banUser(
			this.io, client, payload.roomname, payload.target
		);
	}

	@SubscribeMessage('muteUser')
	handleMuteUser(client: ChatSocket, payload: RoomEventDto) {
		this.chatService.muteUser(
			this.io, client, payload.roomname, payload.target
		);
	}

	@SubscribeMessage('addOperator')
	handleAddOper(client: ChatSocket, payload: RoomEventDto) {
		this.chatService.addOperator(
			this.io, client, payload.roomname, payload.target
		);
	}

	@SubscribeMessage('deleteOperator')
	handleDelOper(client: ChatSocket, payload: RoomEventDto) {
		this.chatService.deleteOperator(
			this.io, client, payload.roomname, payload.target
		);
	}

	//or throw internal server error?
	@SubscribeMessage('requestAllRoomList')
	handleReqAllRoomList(client: ChatSocket) {
		const roomInfo = this.chatService.getAllRoomList(client.userId);
		if (!roomInfo)
			return ;
		client.emit('sendRoomList', roomInfo);
	}

	@SubscribeMessage('requestMyRoomList')
	handleReqUserRoomList(client: ChatSocket) {
		const roomInfo = this.chatService.getUserRoomList(client.userId);
		if (!roomInfo)
			return ;
		client.emit('sendRoomList', roomInfo);
	}

	@SubscribeMessage('requestAllMembers')
	handleReqAllMembers(client: ChatSocket) {
		const members = this.chatService.getAllUserInfo(client.userId);
		if (!members)
			return ;
		client.emit('responseAllMembers', members);
	}


	@SubscribeMessage('requestRoomMembers')
	handleReqRoomMembers(client: ChatSocket, payload: RoomDto) {
		const roomMembers = this.chatService.makeRoomUserInfo(payload.roomname);
		if (!roomMembers)
			return ;
		client.emit('sendRoomMembers', roomMembers);
	}

	@SubscribeMessage('requestTargetMember')
	handleReqTargetMember(client: ChatSocket, payload: UserInfoDto) {
		const member = this.chatService.getUserInfoById(client.userId, payload.targetId);
		if (!member)
			return ;
		client.emit('responseTargetMember', member);
	}

	@SubscribeMessage('requestSearchResultRoomList')
	handleReqQueryRes(client: ChatSocket, payload: NullableTargetDto) {
		const roomInfo = this.chatService.getQueryRoomList(client.userId, payload.target);
		if (!roomInfo)
			return ;
		client.emit('responseRoomQuery', roomInfo);
	}

	updateUserNick(userId: number, newNick: string) {
		this.io.emit("updateUserNick", userId, newNick);
		this.chatService.userChangeNick(this.io, userId, newNick);
	}

	updateUserAvatar(userId: number, filePath: string) {
		this.io.emit("updateUserAvatar", userId, filePath);
		this.chatService.userChangeAvatar(this.io, userId);
	}

	updateUserFriend(userId : number, targetId : number, isAdd : boolean){
		if (isAdd)
			this.io.in(`$${userId}`).emit("follow", targetId);
		else
			this.io.in(`$${userId}`).emit("unfollow", targetId);
	}

	logout(clientId: number) {
		this.chatService.updateUserStatus(this.io, clientId, false);
		this.io.in(`$${clientId}`).disconnectSockets(true);
	}
}
