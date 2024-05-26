import { Body, Controller, Get, Post } from '@nestjs/common';
import { MatchService } from './match.service';
// import internal from 'stream';

@Controller('matchhistory')
export class MatchController {
	constructor (private readonly matchService: MatchService){}

	@Get()
	getAllMatchHistory() : Promise<object[]> {
		return this.matchService.getAllMatchHistory();
	}

	@Post()
	createMatchHistory(@Body() data : {
		winnerId : number ;
		loserId : number ;
	}) : Promise<object> {
		return this.matchService.createMatchHistory(data);
	}
}
