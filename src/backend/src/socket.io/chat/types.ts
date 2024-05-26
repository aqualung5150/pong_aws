import { Socket } from "socket.io"

export type userInfo = {
	id : number;
	nickname : string;
	isGaming : boolean;
	isConnected? : boolean;
	isBlocked? : boolean;
}

export type roomInfo = {
	roomname : string;
	lastMessage : string;
}

export type currRoomInfo = {
	roomname : string;
	owner : string;
	operators : string[];
	messages : formedMessage[];
}

export type formedMessage = {
	from : string;
	fromId? : number;
	to?	: string;
	toId? : number;
	body : string;
	at? : number
}

type JwtPayload = {
    userId: number;
    email: string;
}

type AuthSocket = {
    nickname: string;
	currRoom: string;
}

export type ChatSocket = Socket & JwtPayload & AuthSocket;
