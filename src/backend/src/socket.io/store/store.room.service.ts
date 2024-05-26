import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { Message } from './store.message.service';

export class Room {
	password : string | null;
	owner? : number;
	operators : Set<number>;
	userlist : Set<number>;
	mutelist : Set<number>;
	banlist : Set<number>;
	messages : Message[];
	isPrivate : boolean;

	constructor(
		owner? : number,
		password? : string,
	){
		this.password = password? password : null;
		this.owner = owner? owner : 0;
		this.operators = new Set();
		this.userlist = new Set();
		if (this.owner !== 0)
			this.userlist.add(owner);
		this.mutelist = new Set();
		this.banlist = new Set();
		this.messages = [];
		this.isPrivate = false;
	}

	async isPassword(input : string) : Promise<boolean> {
		return await bcrypt.compare(input, this.password);
	}

	isOwner(userid : number) : boolean {
		return (userid === this.owner);
	}
	
	isOperator(userid : number) : boolean {
		return (this.operators.has(userid));
	}

	isMuted(userid : number) : boolean {
		return (this.mutelist.has(userid));
	}

	isJoinning(userid : number) : boolean {
		return (this.userlist.has(userid));
	}
	
	isBanned(userid : number) : boolean {
		return (this.banlist.has(userid));
	}

	updatePassword(newPassword : string){
		this.password = newPassword;
	}

	updateOwner(newOwner : number){
		this.owner = newOwner;
	}

	addUserToUserlist(userid : number){
		this.userlist.add(userid);
	}

	addUserToBanlist(userid : number){
		this.banlist.add(userid);
		setTimeout(() => {
			this.banlist.delete(userid);
		}, 20000);
	}

	deleteUserFromUserlist(userid : number){
		this.userlist.delete(userid);
	}

	addUserToOperators(userid : number){
		this.operators.add(userid);
	}

	deleteUserFromOperators(userid : number){
		this.operators.delete(userid);
	}

	addUserToMutelist(userid : number){
		this.mutelist.add(userid);
	}

	deleteUserFromMutelist(userid : number){
		this.mutelist.delete(userid);
	}
	
	clearRoom(){
		this.operators = null;
		this.mutelist = null;
		this.banlist = null;
		this.userlist = null;
	}

	storeMessage(from : number, body : string){
		this.messages.push(new Message(from, body));
	}

	getLastMessage(blocklist : Set<number>) : Message {
		if (!blocklist || blocklist.size === 0)
			return (this.messages[this.messages.length - 1]);
		const length = this.messages.length;
		for (let i = length - 1 ; i >= 0 ; i--) {
			if (!blocklist.has(this.messages[i]?.from))
				return (this.messages[i]);
		}
		return (null);
	}
}

interface RoomStore {
  rooms: Map<string, Room>;

  findRoom(roomName: string): Room;
  saveRoom(roomName: string, room: Room): void;
  findAllRoom(): Room[];
  deleteRoom(roomName : string): void;
}

@Injectable()
export class ChatRoomStoreService implements RoomStore{
	rooms = new Map();

	findRoom(roomName: string): Room {
		return this.rooms.get(roomName);
	}

	saveRoom(roomname: string, room: Room): void {
		this.rooms.set(roomname, room);
	}

	findAllRoom(): Room[] {
		return [...this.rooms.values()];
	}

	deleteRoom(roomname: string) : void {
		const target = this.rooms.get(roomname);
		if (target !== undefined)
			target.clearRoom();
		this.rooms.delete(roomname);
	}

	findQueryMatchRoomNames(query : string | null) : string[] {
		const res = [];
		this.rooms.forEach((_, key) => {
			if (key.includes(query)){
				if (this.findRoom(key).isPrivate == false)
					res.push(key);
			}
		})
		return (res);
	}

	/* dmRooms */
	isDMRoom(dmRoomName: string) : boolean {
		if (dmRoomName[0] === '$' && dmRoomName[dmRoomName.length - 1] === '$'){
			if (/^(\d+)\-(\d+)$/.test(dmRoomName.substring(1, dmRoomName.length - 1))){
				return (true);
			}
		}
		return (false);
	}

	getDMRoomname(from : number, to : number) : string {
		return (`$${from}-${to}$`);
	}

	getToIdFromDMRoom(dmRoom : string, userId : number) : string | null {
		const trim = dmRoom.slice(1, dmRoom.length - 1);
		const parts = trim.split('-');
		if (parts[0] === `${userId}`)
			return (parts[1]);
		else
			return (null);
	}

	getFromIdFromDMRoom(dmRoom : string, userId : number) : string | null {
		const trim = dmRoom.slice(1, dmRoom.length - 1);
		const parts = trim.split('-');
		if (parts[1] === `${userId}`)
			return (parts[0]);
		else
			return (null);
	}

	isUserInDMRoom(userId : number, dmRoom : string) : boolean {
		const trim = dmRoom.slice(1, dmRoom.length - 1);
		const parts = trim.split('-');
		if (parts[0] === `${userId}` || parts[1] === `${userId}`)
			return (true);
		else
			return (false);
	}

	parseIdsOfDMRoom(dmRoom : string) : number[] | null {
		if (!this.isDMRoom(dmRoom))
			return (null);
		const trim = dmRoom.slice(1, dmRoom.length - 1);
		const parts = trim.split('-');
		const res = [];
		res.push(Number(parts[0]));
		res.push(Number(parts[1]));
		return (res);
	}
}
