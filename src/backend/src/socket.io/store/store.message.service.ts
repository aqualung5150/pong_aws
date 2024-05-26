import { Injectable } from '@nestjs/common';

export class Message {
	readonly from : number;
	readonly body : string;
	readonly at : number;

	constructor(
		from : number,
		body : string
	){
		this.from = from;
		this.body = body;
		this.at = Date.now();
	}
}

export class DM {
	readonly from : number;
	readonly to : number;
	readonly body : string;
	readonly at : number;

	constructor(
		from : number,
		to : number,
		body : string
	){
		this.from = from,
		this.to = to,
		this.body = body,
		this.at = Date.now();
	}
}

interface DMStore{
	messages: DM[];
	saveMessage(message : DM) : void;
	findMessagesForUser(from : number, to : number) : DM[];
}

@Injectable()
export class ChatMessageStoreService implements DMStore {
	messages = [];
	saveMessage(message: DM): void {
		this.messages.push(message);
	}

	findMessagesForUser(fromId : number, toId : number): DM[] {
		const res = this.messages.filter(
				({ from, to }) => 
				((from ===  fromId && to === toId) || 
				(from === toId && to === fromId))
		);
		return (res);
	}
}
