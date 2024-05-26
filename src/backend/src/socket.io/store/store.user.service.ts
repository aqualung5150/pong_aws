import { Injectable } from '@nestjs/common';

export class User {
	id : number;
	nickname : string;
	blocklist : Set<number>;
	connected : boolean;
	isGaming : boolean;
	joinlist : Set<string>;
	currentRoom : string;
	constructor(id : number, nickname : string){
		this.id = id;
		this.nickname = nickname;
		this.blocklist = new Set();
		this.connected = false;	//
		this.isGaming = false;
		this.joinlist = new Set();
	}

	addUserToBlocklist(userid : number){
		this.blocklist.add(userid);
	}

	deleteUserFromBlockList(userid : number){
		this.blocklist.delete(userid);
	}

	addRoomToJoinlist(roomname : string){
		this.joinlist.add(roomname);
	}

	deleteRoomFromJoinList(roomname : string){
		this.joinlist.delete(roomname);
	}

	clearUser(){
		this.blocklist = null;
		this.joinlist = null;
	}
}

interface UserStore {
	users: Map<number, User>;
	findUserById(id : number) : User;
	saveUser(id : number, user : User): void;
	findAllUser() : User[];
}

@Injectable()
export class ChatUserStoreService implements UserStore{
	users = new Map();
	findUserById(id: number): User | undefined {
		return this.users.get(id);
	}

	//create user if it does not exist and return the instance. no update
	saveUser(id: number, user: User): User {
		const target = this.users.get(id);
		if (target === undefined)
		{
			this.users.set(id, user);
			return (this.users.get(id));
		}
		else
			return (target);
	}

	findAllUser(): User[] {
		return [...this.users.values()];
	}

	getNicknameById(id : number) : string | null {
		const user = this.findUserById(id);
		if (user === undefined)
			return (null);
		else
			return (user.nickname);
	}

	getIdByNickname(nickname : string) : number {
		const res = this.findAllUser().find((user) => user.nickname === nickname);
		return (res ? res.id : -1);
	}
}
